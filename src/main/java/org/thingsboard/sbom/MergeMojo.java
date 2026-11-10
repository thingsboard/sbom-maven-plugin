// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
package org.thingsboard.sbom;

import org.apache.maven.artifact.Artifact;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.plugins.annotations.ResolutionScope;
import org.apache.maven.project.MavenProject;

import java.io.File;

/**
 * Merges a CycloneDX SBOM embedded in a runtime dependency (the host) into the project's SBOM.
 * The nested SBOM's root is replaced by the host component, its components and dependency graph are appended,
 * and its tools are added to {@code metadata.tools}. The target file is left untouched when any check fails.
 * Runs at {@code process-resources} by default, after {@code cyclonedx-maven-plugin:makeBom} bound to {@code generate-resources}.
 */
@Mojo(name = "merge", defaultPhase = LifecyclePhase.PROCESS_RESOURCES, requiresDependencyResolution = ResolutionScope.RUNTIME, threadSafe = true)
public class MergeMojo extends SbomMojo {

    @Parameter(defaultValue = "${project}", readonly = true, required = true)
    private MavenProject project;

    /**
     * SBOM to merge into, rewritten in place.
     */
    @Parameter(property = "sbom.merge.targetFile", defaultValue = "${project.build.outputDirectory}/META-INF/sbom/application.cdx.json", required = true)
    private File targetFile;

    /**
     * {@code groupId:artifactId} of the runtime dependency that carries the nested SBOM.
     */
    @Parameter(property = "sbom.merge.host", required = true)
    private String host;

    /**
     * Path of the nested SBOM inside the host jar or classes directory.
     * Defaults to {@code META-INF/sbom/<artifactId>.cdx.json}, where {@code <artifactId>} is the host's.
     */
    @Parameter(property = "sbom.merge.resource")
    private String resource;

    /**
     * Skip the merge.
     */
    @Parameter(property = "sbom.merge.skip", defaultValue = "false")
    private boolean skip;

    @Override
    boolean isSkipped() {
        return skip;
    }

    @Override
    String description() {
        return "SBOM merge";
    }

    @Override
    void run() throws MojoFailureException {
        String[] coordinates = host == null ? new String[0] : host.split(":", -1);
        if (coordinates.length != 2 || coordinates[0].isBlank() || coordinates[1].isBlank()) {
            throw new MojoFailureException("host must be groupId:artifactId, got '" + host + "'");
        }
        String groupId = coordinates[0];
        String artifactId = coordinates[1];
        Artifact hostArtifact = project.getArtifacts().stream()
                .filter(artifact -> artifact.getGroupId().equals(groupId) && artifact.getArtifactId().equals(artifactId))
                .findFirst()
                .orElseThrow(() -> new MojoFailureException(host + " is not a runtime dependency of " + project.getId()));
        File source = hostArtifact.getFile();
        if (source == null) {
            throw new MojoFailureException(host + " is not resolved to a file");
        }
        String nestedResource = resource == null || resource.isBlank() ? "META-INF/sbom/" + artifactId + ".cdx.json" : resource;
        int merged = SbomMerger.mergeFile(targetFile.toPath(), source.toPath(), nestedResource, "pkg:maven/" + groupId + "/" + artifactId + "@");
        getLog().info("Merged " + merged + " components from " + host + " (" + nestedResource + ") into " + targetFile);
    }

}
