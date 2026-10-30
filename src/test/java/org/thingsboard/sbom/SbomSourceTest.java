package org.thingsboard.sbom;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SbomSourceTest {

    private static final String RESOURCE = "META-INF/sbom/ui-ngx.cdx.json";

    @TempDir
    Path tempDir;

    @Test
    void readsTheResourceFromAJar() throws IOException {
        Path jar = jar(RESOURCE, Boms.npmFixture().toString());

        JsonNode bom = SbomSource.readResource(jar, RESOURCE);

        assertThat(bom).isEqualTo(Boms.npmFixture());
    }

    @Test
    void readsTheResourceFromAClassesDirectory() throws IOException {
        Path file = tempDir.resolve(RESOURCE);
        Files.createDirectories(file.getParent());
        Files.writeString(file, Boms.npmFixture().toString());

        JsonNode bom = SbomSource.readResource(tempDir, RESOURCE);

        assertThat(bom).isEqualTo(Boms.npmFixture());
    }

    @Test
    void failsWhenTheJarHasNoSuchResource() throws IOException {
        Path jar = jar("META-INF/other.json", "{}");

        assertThatThrownBy(() -> SbomSource.readResource(jar, RESOURCE))
                .isInstanceOf(SbomMergeException.class)
                .hasMessageContaining(RESOURCE + " not found in " + jar);
    }

    @Test
    void failsWhenTheDirectoryHasNoSuchResource() {
        assertThatThrownBy(() -> SbomSource.readResource(tempDir, RESOURCE))
                .isInstanceOf(SbomMergeException.class)
                .hasMessageContaining(RESOURCE + " not found in " + tempDir);
    }

    @Test
    void failsWhenTheSourceDoesNotExist() {
        Path missing = tempDir.resolve("missing.jar");

        assertThatThrownBy(() -> SbomSource.readResource(missing, RESOURCE))
                .isInstanceOf(SbomMergeException.class)
                .hasMessageContaining("SBOM source " + missing + " does not exist");
    }

    @Test
    void failsWhenTheSourceIsNotAZip() throws IOException {
        Path notAJar = Files.writeString(tempDir.resolve("broken.jar"), "not a zip");

        assertThatThrownBy(() -> SbomSource.readResource(notAJar, RESOURCE))
                .isInstanceOf(SbomMergeException.class)
                .hasMessageContaining("Failed to read " + RESOURCE + " from " + notAJar);
    }

    @Test
    void failsWhenTheResourceIsNotJson() throws IOException {
        Path jar = jar(RESOURCE, "{ not json");

        assertThatThrownBy(() -> SbomSource.readResource(jar, RESOURCE))
                .isInstanceOf(SbomMergeException.class)
                .hasMessageContaining("Failed to read " + RESOURCE + " from " + jar);
    }

    @Test
    void failsWhenTheFileDoesNotExist() {
        Path missing = tempDir.resolve("application.cdx.json");

        assertThatThrownBy(() -> SbomSource.readFile(missing))
                .isInstanceOf(SbomMergeException.class)
                .hasMessageContaining("SBOM file " + missing + " does not exist");
    }

    @Test
    void failsWhenTheFileIsNotJson() throws IOException {
        Path file = Files.writeString(tempDir.resolve("application.cdx.json"), "{ not json");

        assertThatThrownBy(() -> SbomSource.readFile(file))
                .isInstanceOf(SbomMergeException.class)
                .hasMessageContaining("SBOM file " + file + " is not valid JSON");
    }

    private Path jar(String entryName, String content) throws IOException {
        Path jar = tempDir.resolve("ui-ngx.jar");
        try (OutputStream out = Files.newOutputStream(jar); ZipOutputStream zip = new ZipOutputStream(out)) {
            zip.putNextEntry(new ZipEntry(entryName));
            zip.write(content.getBytes(StandardCharsets.UTF_8));
            zip.closeEntry();
        }
        return jar;
    }

}
