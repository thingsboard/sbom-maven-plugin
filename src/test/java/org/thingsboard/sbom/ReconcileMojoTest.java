// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
package org.thingsboard.sbom;

import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.DefaultArtifact;
import org.apache.maven.artifact.handler.DefaultArtifactHandler;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.thingsboard.sbom.JarLibraries.Library;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ReconcileMojoTest {

    @TempDir
    Path dir;

    @Test
    void aResolvedArtifactWithTheNameAndContentOfThePackedLibraryGivesItsComponent() throws IOException {
        Artifact artifact = artifact("ffi", "2.0", "native", "jar");

        Optional<ObjectNode> component = ReconcileMojo.resolved(List.of(artifact("core", "1.0", null, "jar"), artifact), packed(artifact));

        assertThat(component.orElseThrow().get("purl").asText()).isEqualTo("pkg:maven/org.example/ffi@2.0?classifier=native&type=jar");
    }

    @Test
    void aResolvedArtifactOfAnotherTypeKeepsItsTypeInThePurl() throws IOException {
        Artifact artifact = artifact("core", "1.0", "tests", "test-jar");

        Optional<ObjectNode> component = ReconcileMojo.resolved(List.of(artifact), packed(artifact));

        assertThat(component.orElseThrow().get("purl").asText()).isEqualTo("pkg:maven/org.example/core@1.0?classifier=tests&type=test-jar");
    }

    @Test
    void aPackedLibraryWithOtherContentThanTheResolvedArtifactIsRefused() throws IOException {
        Library packed = new Library("core-1.0.jar", Map.of("SHA-256", "0".repeat(64)));

        assertThatThrownBy(() -> ReconcileMojo.resolved(List.of(artifact("core", "1.0", null, "jar")), packed))
                .isInstanceOf(SbomException.class).hasMessageContaining("core-1.0.jar with other content than the file Maven resolved");
    }

    @Test
    void anArtifactWithoutFileOrWithAnotherNameOrThatIsNotAJarIsNotTheLibrary() throws IOException {
        Artifact unresolved = new DefaultArtifact("org.example", "core", "1.0", "compile", "jar", null, new DefaultArtifactHandler("jar"));
        Artifact notAJar = artifact("core", "1.0", null, "pom");
        Library packed = new Library("core-1.0.jar", Map.of("SHA-256", "0".repeat(64)));

        assertThat(ReconcileMojo.resolved(List.of(unresolved, notAJar, artifact("ffi", "2.0", null, "jar")), packed)).isEmpty();
    }

    /**
     * An artifact with a file of its own content. Every type but pom has a jar as its file here.
     */
    private Artifact artifact(String artifactId, String version, String classifier, String type) throws IOException {
        DefaultArtifactHandler handler = new DefaultArtifactHandler(type);
        handler.setExtension("pom".equals(type) ? "pom" : "jar");
        Artifact artifact = new DefaultArtifact("org.example", artifactId, version, "compile", type, classifier, handler);
        Path file = dir.resolve(SbomReconciler.fileName(artifactId, version, classifier));
        Files.write(file, (artifactId + type).getBytes(StandardCharsets.UTF_8));
        artifact.setFile(file.toFile());
        return artifact;
    }

    private static Library packed(Artifact artifact) {
        return new Library(artifact.getFile().getName(), SbomFiles.hashes(artifact.getFile().toPath()));
    }

}
