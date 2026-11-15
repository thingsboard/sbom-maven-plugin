// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
package org.thingsboard.sbom;

import org.apache.maven.RepositoryUtils;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.project.MavenProject;
import org.eclipse.aether.DefaultRepositorySystemSession;
import org.eclipse.aether.RepositorySystem;
import org.eclipse.aether.artifact.Artifact;
import org.eclipse.aether.artifact.ArtifactProperties;
import org.eclipse.aether.artifact.ArtifactTypeRegistry;
import org.eclipse.aether.collection.CollectRequest;
import org.eclipse.aether.collection.DependencyCollectionException;
import org.eclipse.aether.graph.DependencyNode;
import org.eclipse.aether.util.artifact.JavaScopes;
import org.eclipse.aether.util.graph.manager.DependencyManagerUtils;
import org.eclipse.aether.util.graph.transformer.ConflictResolver;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * The dependency graph of a project as Maven resolves it, by purl: who depends on whom, without the test dependencies.
 * A dependency that lost a version conflict is the edge to the version that won, so the graph keeps every edge of the
 * poms, as the graph of {@code cyclonedx-maven-plugin} does.
 */
final class MavenGraph {
    private MavenGraph() {}

    /**
     * @return what each artifact depends on, the project first
     */
    static Map<String, Set<String>> collect(MavenSession session, MavenProject project, RepositorySystem repositorySystem) {
        DefaultRepositorySystemSession repositorySession = new DefaultRepositorySystemSession(session.getRepositorySession());
        // Keeps the dependencies that lost a conflict in the graph, each with a link to the one that won
        repositorySession.setConfigProperty(ConflictResolver.CONFIG_PROP_VERBOSE, true);
        repositorySession.setConfigProperty(DependencyManagerUtils.CONFIG_PROP_VERBOSE, true);
        ArtifactTypeRegistry types = repositorySession.getArtifactTypeRegistry();
        CollectRequest request = new CollectRequest();
        request.setRootArtifact(RepositoryUtils.toArtifact(project.getArtifact()));
        request.setRepositories(project.getRemoteProjectRepositories());
        project.getDependencies().forEach(dependency -> request.addDependency(RepositoryUtils.toDependency(dependency, types)));
        if (project.getDependencyManagement() != null) {
            project.getDependencyManagement().getDependencies().forEach(dependency -> request.addManagedDependency(RepositoryUtils.toDependency(dependency, types)));
        }
        DependencyNode root;
        try {
            root = repositorySystem.collectDependencies(repositorySession, request).getRoot();
        } catch (DependencyCollectionException e) {
            throw new SbomException("The dependency graph of " + project.getId() + " could not be collected: " + e.getMessage(), e);
        }
        Map<String, Set<String>> graph = new LinkedHashMap<>();
        add(graph, root, null, null);
        return graph;
    }

    private static void add(Map<String, Set<String>> graph, DependencyNode node, String parent, String parentWithoutClassifier) {
        if (type(node.getArtifact()) == null || parent != null && JavaScopes.TEST.equals(originalScope(node))) {
            return;
        }
        if (node.getChildren().isEmpty() && node.getData().get(ConflictResolver.NODE_DATA_WINNER) instanceof DependencyNode winner) {
            node = winner;
        }
        Artifact artifact = node.getArtifact();
        String purl = purl(artifact, artifact.getClassifier());
        if (!graph.containsKey(purl)) {
            graph.put(purl, new LinkedHashSet<>());
            // An artifact that depends on itself with another classifier, and that one on it, is not followed in a circle
            String withoutClassifier = purl(artifact, null);
            if (!withoutClassifier.equals(parentWithoutClassifier)) {
                for (DependencyNode child : node.getChildren()) {
                    add(graph, child, purl, withoutClassifier);
                }
            }
        }
        if (parent != null) {
            graph.get(parent).add(purl);
        }
    }

    private static String originalScope(DependencyNode node) {
        Object original = node.getData().get(ConflictResolver.NODE_DATA_ORIGINAL_SCOPE);
        return original != null ? original.toString() : node.getDependency().getScope();
    }

    private static String type(Artifact artifact) {
        return artifact.getProperties().get(ArtifactProperties.TYPE);
    }

    private static String purl(Artifact artifact, String classifier) {
        return MavenComponents.purl(artifact.getGroupId(), artifact.getArtifactId(), artifact.getBaseVersion(), type(artifact), classifier);
    }
}
