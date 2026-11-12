// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
package org.thingsboard.sbom;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.handler.manager.ArtifactHandlerManager;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.plugins.annotations.ResolutionScope;
import org.apache.maven.project.MavenProject;
import org.thingsboard.sbom.JarLibraries.Library;

import javax.inject.Inject;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

/**
 * Makes the project's SBOM equal to what the packaging put into the jar, and puts the corrected SBOM into the jar.
 * The SBOM is made from Maven's dependency graph before the jar exists, and the packaging does not pack exactly that graph:
 * Spring Boot adds a library of its own and leaves the starters out, and an SBOM tool can miss one of two artifacts that
 * differ only by classifier. This goal reads the libraries of the finished jar, adds the components the SBOM lacks,
 * removes the components that were not packed, and corrects hashes that differ. The build fails for a packed library
 * that is neither a Maven dependency of the project nor declared in {@code libraries}.
 * Bind it after the goal that packs the jar and before anything that reads the jar or the SBOM.
 */
@Mojo(name = "reconcile", defaultPhase = LifecyclePhase.PACKAGE, requiresDependencyResolution = ResolutionScope.COMPILE_PLUS_RUNTIME, threadSafe = true)
public class ReconcileMojo extends SbomMojo {

    @Parameter(defaultValue = "${project}", readonly = true, required = true)
    private MavenProject project;

    /**
     * Knows the file extension of every artifact type of the build, those of build extensions included.
     */
    @Inject
    private ArtifactHandlerManager artifactHandlerManager;

    /**
     * The jar that packs the libraries.
     */
    @Parameter(property = "sbom.reconcile.jar", defaultValue = "${project.build.directory}/${project.build.finalName}.jar", required = true)
    private File jar;

    /**
     * The directory of the jar that holds the libraries.
     */
    @Parameter(property = "sbom.reconcile.libraryDirectory", defaultValue = "BOOT-INF/lib")
    private String libraryDirectory;

    /**
     * SBOM to correct, rewritten in place.
     */
    @Parameter(property = "sbom.reconcile.sbomFile", defaultValue = "${project.build.outputDirectory}/META-INF/sbom/application.cdx.json", required = true)
    private File sbomFile;

    /**
     * Path of the SBOM inside a jar. It is replaced in {@code jar}, which must embed it, and in each of {@code otherJars}.
     */
    @Parameter(property = "sbom.reconcile.resource", defaultValue = "META-INF/sbom/application.cdx.json")
    private String resource;

    /**
     * Other jars of the project that embed the same SBOM, such as the jar that Spring Boot repackaged.
     * A jar that does not exist or does not embed the SBOM is passed over.
     */
    @Parameter
    private List<File> otherJars = new ArrayList<>();

    /**
     * Libraries that the packaging adds to the jar and that are not Maven dependencies of the project.
     */
    @Parameter
    private List<PackedLibrary> libraries = new ArrayList<>();

    /**
     * Skip the reconciliation.
     */
    @Parameter(property = "sbom.reconcile.skip", defaultValue = "false")
    private boolean skip;

    @Override
    boolean isSkipped() {
        return skip;
    }

    @Override
    String description() {
        return "SBOM reconciliation with the jar";
    }

    @Override
    void run() {
        Path jarPath = jar.toPath();
        Path sbomPath = sbomFile.toPath();
        SbomChecks.check(Files.isRegularFile(jarPath), "Jar " + jarPath + " does not exist. Bind this goal after the goal that packs it");
        JsonNode source = SbomFiles.readFile(sbomPath);
        List<Library> packed = JarLibraries.read(jarPath, libraryDirectory);
        SbomChecks.check(!packed.isEmpty(), "Jar " + jarPath + " packs no libraries in " + libraryDirectory
                + ". Set the jar parameter to the jar that packs them");
        SbomChecks.check(JarLibraries.hasEntry(jarPath, resource), "Jar " + jarPath + " does not embed the SBOM at " + resource
                + ", so a corrected SBOM could not be put into it. Set the resource parameter to the path of the SBOM inside the jar");
        SbomReconciler.Result result = SbomReconciler.reconcile(source, packed,
                type -> "jar".equals(artifactHandlerManager.getArtifactHandler(type).getExtension()), library -> identify(library, source));

        result.added().forEach(ref -> getLog().info("Added to the SBOM, packed but not listed: " + ref));
        result.removed().forEach(ref -> getLog().info("Removed from the SBOM, listed but not packed: " + ref));
        result.rehashed().forEach(ref -> getLog().info("Hashes corrected to those of the packed file: " + ref));
        if (!result.changed()) {
            getLog().info("The SBOM lists exactly the " + packed.size() + " libraries of " + jarPath.getFileName());
            return;
        }
        byte[] content = SbomFiles.writeFile(sbomPath, result.bom());
        JarEntryReplacer.replace(jarPath, resource, content);
        getLog().info("Replaced " + resource + " in " + jar);
        for (File other : otherJars) {
            if (other.isFile() && JarEntryReplacer.replace(other.toPath(), resource, content)) {
                getLog().info("Replaced " + resource + " in " + other);
            }
        }
        getLog().info("Reconciled " + sbomFile + " with the " + packed.size() + " libraries of " + jarPath.getFileName()
                + ": " + result.added().size() + " added, " + result.removed().size() + " removed, " + result.rehashed().size() + " rehashed");
    }

    /**
     * A component for a packed library that the SBOM does not list: a Maven dependency of the project that the SBOM tool
     * missed, or else a declared library.
     */
    private Optional<ObjectNode> identify(Library library, JsonNode bom) {
        Optional<ObjectNode> resolved = resolved(project.getArtifacts(), library);
        resolved.ifPresent(component -> SbomReconciler.copyPomFields(bom, component));
        return resolved.or(() -> SbomReconciler.declared(libraries, library.fileName(),
                () -> JarLibraries.implementationVersion(jar.toPath(), libraryDirectory, library.fileName())));
    }

    /**
     * A component for the artifact, among those Maven resolved, whose file has the name of the packed library.
     */
    static Optional<ObjectNode> resolved(Collection<Artifact> artifacts, Library library) {
        for (Artifact artifact : artifacts) {
            File file = artifact.getFile();
            if (file == null || !file.isFile() || !isJar(artifact)
                    || !SbomReconciler.fileName(artifact.getArtifactId(), artifact.getBaseVersion(), artifact.getClassifier()).equals(library.fileName())) {
                continue;
            }
            SbomChecks.check(library.sha256().equals(SbomFiles.hashes(file.toPath()).get("SHA-256")),
                    "The jar packs " + library.fileName() + " with other content than the file Maven resolved: " + file);
            return Optional.of(SbomReconciler.mavenComponent(artifact.getGroupId(), artifact.getArtifactId(), artifact.getBaseVersion(), artifact.getClassifier(), artifact.getType()));
        }
        return Optional.empty();
    }

    private static boolean isJar(Artifact artifact) {
        return "jar".equals(artifact.getArtifactHandler().getExtension());
    }

}
