// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
package org.thingsboard.sbom;

import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.DefaultArtifact;
import org.apache.maven.artifact.handler.DefaultArtifactHandler;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.thingsboard.sbom.JarLibraries.Library;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JarMojoTest {

    @TempDir
    Path dir;

    @Test
    void aDependencyHasTheFileNameMavenGivesItWithItsClassifier() throws IOException {
        Artifact plain = artifact("org.example", "a", "1.0", null, "jar");
        Artifact classified = artifact("org.example", "a", "1.0", "native", "jar");
        Artifact tests = artifact("org.example", "b", "2.0", "tests", "test-jar");

        Map<String, Artifact> byFileName = JarMojo.artifactsByFileName(List.of(plain, classified, tests));

        assertThat(byFileName).containsEntry("a-1.0.jar", plain).containsEntry("a-1.0-native.jar", classified).containsEntry("b-2.0-tests.jar", tests);
    }

    @Test
    void twoDependenciesWithOneFileNameAreFoundByTheNameAfterTheirGroup() throws IOException {
        Artifact first = artifact("org.first", "core", "1.0", null, "jar");
        Artifact second = artifact("org.second", "core", "1.0", null, "jar");

        Map<String, Artifact> byFileName = JarMojo.artifactsByFileName(List.of(first, second));

        assertThat(byFileName).containsEntry("org.first-core-1.0.jar", first).containsEntry("org.second-core-1.0.jar", second);
    }

    @Test
    void aSnapshotHasItsBaseVersionInTheFileName() throws IOException {
        Artifact snapshot = artifact("org.example", "a", "1.0-20260101.120000-1", null, "jar");
        snapshot.setBaseVersion("1.0-SNAPSHOT");

        assertThat(JarMojo.artifactsByFileName(List.of(snapshot))).containsKey("a-1.0-SNAPSHOT.jar");
    }

    @Test
    void aDependencyThatIsNoJarOrHasNoFileIsNotAPackedLibrary() throws IOException {
        Artifact pom = artifact("org.example", "bom", "1.0", null, "pom");
        Artifact unresolved = new DefaultArtifact("org.example", "a", "1.0", "compile", "jar", null, new DefaultArtifactHandler("jar"));
        Artifact classes = new DefaultArtifact("org.example", "module", "1.0", "compile", "jar", null, new DefaultArtifactHandler("jar"));
        classes.setFile(dir.toFile());

        assertThat(JarMojo.artifactsByFileName(List.of(pom, unresolved, classes))).isEmpty();
    }

    @Test
    void aPackedLibraryWithOtherContentThanTheResolvedFileIsRefused() throws IOException {
        Path resolved = Files.writeString(dir.resolve("a-1.0.jar"), "resolved");
        String sha256 = SbomFiles.hashes(resolved, List.of("SHA-256")).get("SHA-256");

        assertThatCode(() -> JarMojo.checkSameContent(resolved, new Library("a-1.0.jar", Map.of("SHA-256", sha256)))).doesNotThrowAnyException();
        assertThatThrownBy(() -> JarMojo.checkSameContent(resolved, new Library("a-1.0.jar", Map.of("SHA-256", "0".repeat(64)))))
                .isInstanceOf(SbomException.class).hasMessageContaining("a-1.0.jar with other content than the file Maven resolved");
    }

    @Test
    void theLibraryOfANestedSbomIsAGroupAndAnArtifactId() {
        assertThat(new NestedSbom("org.example:ui", null).coordinates()).containsExactly("org.example", "ui");
        assertThat(new NestedSbom("org.example:ui", null).resourceOr("default.json")).isEqualTo("default.json");
        assertThat(new NestedSbom("org.example:ui", "META-INF/ui.json").resourceOr("default.json")).isEqualTo("META-INF/ui.json");
        for (String library : new String[] {null, "ui", "org.example:", ":ui", "org.example:ui:1.0"}) {
            assertThatThrownBy(() -> new NestedSbom(library, null).coordinates())
                    .isInstanceOf(SbomException.class).hasMessageContaining("must be groupId:artifactId");
        }
    }

    private Artifact artifact(String group, String name, String version, String classifier, String type) throws IOException {
        String extension = "pom".equals(type) ? "pom" : "jar";
        Artifact artifact = new DefaultArtifact(group, name, version, "compile", type, classifier, new DefaultArtifactHandler(extension));
        Path file = Files.createDirectories(dir.resolve(group)).resolve(name + "-" + version + (classifier == null ? "" : "-" + classifier) + "." + extension);
        artifact.setFile(Files.writeString(file, group + name).toFile());
        return artifact;
    }

}
