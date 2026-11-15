// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
package org.thingsboard.sbom;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.handler.manager.ArtifactHandlerManager;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugin.descriptor.PluginDescriptor;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.plugins.annotations.ResolutionScope;
import org.apache.maven.project.MavenProject;
import org.apache.maven.project.ProjectBuilder;
import org.cyclonedx.model.Component;
import org.eclipse.aether.RepositorySystem;
import org.thingsboard.sbom.JarLibraries.Library;

import javax.inject.Inject;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Makes the SBOM of a jar that packs its libraries, such as a Spring Boot jar, from the finished jar: one component for
 * every library in it, described by the pom of the library, with the dependency graph that Maven resolves between them.
 * The SBOM is written to a file and put into the jar. So it lists what the jar ships, whatever the packaging added to
 * the dependencies of the project or left out of them.
 * <p>
 * Bind the goal after the goal that packs the jar and before anything that reads the jar or the SBOM.
 */
@Mojo(name = "jar", defaultPhase = LifecyclePhase.PACKAGE, requiresDependencyResolution = ResolutionScope.COMPILE_PLUS_RUNTIME, threadSafe = true)
public class JarMojo extends SbomMojo {
    private static final String SPRING_BOOT_VERSION = "Spring-Boot-Version";

    @Parameter(defaultValue = "${project}", readonly = true, required = true)
    private MavenProject project;

    @Parameter(defaultValue = "${session}", readonly = true, required = true)
    private MavenSession session;

    @Parameter(defaultValue = "${plugin}", readonly = true, required = true)
    private PluginDescriptor plugin;

    @Inject
    private ArtifactHandlerManager artifactHandlerManager;

    @Inject
    private ProjectBuilder projectBuilder;

    @Inject
    private RepositorySystem repositorySystem;

    /**
     * The jar that packs the libraries. The build fails when it packs none.
     */
    @Parameter(property = "sbom.jar.jar", defaultValue = "${project.build.directory}/${project.build.finalName}.jar", required = true)
    private File jar;

    /**
     * The directory of the jar that holds the libraries.
     */
    @Parameter(property = "sbom.jar.libraryDirectory", defaultValue = "BOOT-INF/lib")
    private String libraryDirectory;

    /**
     * Where the SBOM is written. Not in the output directory of the project, where a later build without {@code clean}
     * would pack the SBOM of this one.
     */
    @Parameter(property = "sbom.jar.sbomFile", defaultValue = "${project.build.directory}/sbom/application.cdx.json", required = true)
    private File sbomFile;

    /**
     * Path of the SBOM inside a jar. A Spring Boot jar also gets the {@code Sbom-Location} and {@code Sbom-Format} of its manifest,
     * as Spring Boot sets them for an SBOM it finds when it packs the jar.
     */
    @Parameter(property = "sbom.jar.resource", defaultValue = "META-INF/sbom/application.cdx.json")
    private String resource;

    /**
     * Other jars of the project that get the same SBOM, such as the plain jar next to a Spring Boot jar. One that does not exist is passed over.
     */
    @Parameter
    private List<File> otherJars = new ArrayList<>();

    /**
     * Libraries that the packaging adds and that are not Maven dependencies of the project: {@code group} and {@code name}.
     */
    @Parameter
    private List<PackedLibrary> libraries = new ArrayList<>();

    /**
     * Packed libraries that carry the SBOM of what they bundle: {@code library} ({@code groupId:artifactId}), and optionally
     * {@code resource} (path of the SBOM inside the library, {@code META-INF/sbom/<artifactId>.cdx.json} by default) and {@code skip}.
     */
    @Parameter
    private List<NestedSbom> nestedSboms = new ArrayList<>();

    /**
     * CycloneDX type of the component of the project.
     */
    @Parameter(property = "sbom.jar.projectType", defaultValue = "application")
    private String projectType;

    /**
     * Organization that created the SBOM; sets {@code metadata.manufacturer}.
     */
    @Parameter
    private Organization manufacturer;

    /**
     * Organization that supplies the software the SBOM describes; sets {@code metadata.supplier}.
     */
    @Parameter
    private Organization supplier;

    /**
     * Organization that created the software the SBOM describes; sets {@code metadata.component.manufacturer}.
     */
    @Parameter
    private Organization componentManufacturer;

    /**
     * When the SBOM was made; sets {@code metadata.timestamp}. By default the time Maven builds reproducibly with: a date and time
     * with an offset ({@code 2026-01-31T12:00:00Z}) or seconds since 1970. Not set, or left at the {@code 1980-02-01T00:00:00Z}
     * that Maven sets by itself, it is the time the goal runs.
     */
    @Parameter(property = "sbom.jar.timestamp", defaultValue = "${project.build.outputTimestamp}")
    private String timestamp;

    /**
     * Skip the SBOM of the jar.
     */
    @Parameter(property = "sbom.jar.skip", defaultValue = "false")
    private boolean skip;

    @Override
    boolean isSkipped() {
        return skip;
    }

    @Override
    String description() {
        return "SBOM of the jar";
    }

    @Override
    void run() throws MojoFailureException {
        Path jarPath = jar.toPath();
        SbomChecks.check(Files.isRegularFile(jarPath), "Jar " + jarPath + " does not exist. Bind this goal after the goal that packs it");
        List<Library> packed = JarLibraries.read(jarPath, libraryDirectory);
        SbomChecks.check(!packed.isEmpty(), "Jar " + jarPath + " packs no libraries in " + libraryDirectory
                + ". Set the jar parameter to the jar that packs them");

        MavenComponents maven = new MavenComponents(session, project, projectBuilder, artifactHandlerManager);
        Map<String, Artifact> artifacts = artifactsByFileName(project.getArtifacts());
        List<Component> components = new ArrayList<>();
        Set<String> dependencies = new LinkedHashSet<>();
        List<String> unknown = new ArrayList<>();
        for (Library library : packed) {
            Artifact artifact = artifacts.get(library.fileName());
            Component component = artifact != null ? dependency(maven, artifact, library) : declared(maven, jarPath, library);
            if (component == null) {
                unknown.add(library.fileName());
                continue;
            }
            component.setHashes(MavenComponents.hashes(library.hashes()));
            components.add(component);
            if (artifact != null) {
                dependencies.add(component.getBomRef());
            }
        }
        SbomChecks.check(unknown.isEmpty(), "The jar packs libraries that are not Maven dependencies of the project: "
                + String.join(", ", unknown) + ". Declare each of them in the libraries parameter of the goal");

        String time = SbomMetadata.timestamp(timestamp);
        Map<String, Set<String>> graph = MavenGraph.collect(session, project, repositorySystem);
        dependencies.removeAll(graph.keySet());
        dependencies.forEach(ref -> getLog().info("Maven's dependency graph does not have " + ref + ": its place in the SBOM is what the poms of the libraries say"));
        JarSbom.linkByPoms(graph, dependencies, maven.poms())
                .forEach(ref -> getLog().warn("No pom of a packed library names " + ref + ", so the SBOM makes it a dependency of the project"));
        ObjectNode bom = JarSbom.bom(maven.root(project, projectType), MavenComponents.tool(plugin), components, graph, time != null);
        for (NestedSbom nested : nestedSboms) {
            if (!nested.isSkip()) {
                bom = merge(bom, nested);
            }
        }
        if (manufacturer != null || supplier != null || componentManufacturer != null || time != null) {
            bom = SbomMetadata.apply(bom, manufacturer, supplier, componentManufacturer, time);
        }
        SbomChecks.checkInput("Jar", bom);

        byte[] content = SbomFiles.writeFile(sbomFile.toPath(), bom);
        put(jarPath, content);
        for (File other : otherJars) {
            if (other.isFile()) {
                put(other.toPath(), content);
            }
        }
        getLog().info("Wrote " + sbomFile + " with the " + packed.size() + " libraries of " + jarPath.getFileName());
    }

    /**
     * The dependencies of the project whose file is a jar, by the name Spring Boot gives the file when it packs it:
     * the name Maven gives it, after the group when two dependencies have that name.
     */
    static Map<String, Artifact> artifactsByFileName(Collection<Artifact> dependencies) {
        Map<String, Artifact> byName = new HashMap<>();
        Map<String, Artifact> afterGroup = new HashMap<>();
        for (Artifact artifact : dependencies) {
            if (artifact.getFile() == null || !artifact.getFile().isFile() || !"jar".equals(artifact.getArtifactHandler().getExtension())) {
                continue;
            }
            String classifier = artifact.getClassifier();
            String name = artifact.getArtifactId() + "-" + artifact.getBaseVersion() + (classifier == null || classifier.isEmpty() ? "" : "-" + classifier) + ".jar";
            byName.putIfAbsent(name, artifact);
            afterGroup.put(artifact.getGroupId() + "-" + name, artifact);
        }
        afterGroup.forEach(byName::putIfAbsent);
        return byName;
    }

    private static Component dependency(MavenComponents maven, Artifact artifact, Library library) {
        checkSameContent(artifact.getFile().toPath(), library);
        return maven.library(artifact);
    }

    static void checkSameContent(Path resolved, Library library) {
        SbomChecks.check(library.sha256().equals(SbomFiles.hashes(resolved, List.of("SHA-256")).get("SHA-256")),
                "The jar packs " + library.fileName() + " with other content than the file Maven resolved: " + resolved);
    }

    private Component declared(MavenComponents maven, Path jarPath, Library library) {
        for (PackedLibrary declared : libraries) {
            String version = declared.versionIn(library.fileName(), () -> JarLibraries.implementationVersion(jarPath, libraryDirectory, library.fileName()));
            if (version == null) {
                continue;
            }
            SbomChecks.check(declared.getGroup() != null && !declared.getGroup().isBlank(), "Library " + declared.getName() + " has no group");
            return maven.library(declared.getGroup(), declared.getName(), version);
        }
        return null;
    }

    private ObjectNode merge(ObjectNode bom, NestedSbom nested) throws MojoFailureException {
        String[] coordinates = nested.coordinates();
        Artifact host = project.getArtifacts().stream()
                .filter(artifact -> artifact.getGroupId().equals(coordinates[0]) && artifact.getArtifactId().equals(coordinates[1]) && artifact.getFile() != null)
                .findFirst()
                .orElseThrow(() -> new MojoFailureException(nested.getLibrary() + " is not a dependency of " + project.getId()));
        String path = nested.resourceOr("META-INF/sbom/" + coordinates[1] + ".cdx.json");
        JsonNode sbom = SbomFiles.readResource(host.getFile().toPath(), path);
        getLog().info("Adding " + sbom.path("components").size() + " components from " + nested.getLibrary() + " (" + path + ")");
        return SbomMerger.merge(bom, sbom, "pkg:maven/" + coordinates[0] + "/" + coordinates[1] + "@");
    }

    private void put(Path target, byte[] content) {
        Map<String, String> attributes = JarEntries.manifestAttribute(target, SPRING_BOOT_VERSION) == null ? Map.of()
                : Map.of("Sbom-Location", resource, "Sbom-Format", "CycloneDX");
        JarEntries.put(target, resource, content, attributes);
        getLog().info("Put " + resource + " into " + target);
    }
}
