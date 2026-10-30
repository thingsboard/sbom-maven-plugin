package org.thingsboard.sbom;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SbomMergerFileTest {

    private static final String RESOURCE = "META-INF/sbom/ui-ngx.cdx.json";

    @TempDir
    Path tempDir;

    @Test
    void mergesTheResourceIntoTheTargetFileInPlace() throws IOException {
        Path target = Files.writeString(tempDir.resolve("application.cdx.json"), Boms.mavenFixture().toPrettyString());
        Path source = uiNgxClasses(Boms.npmFixture().toString());

        int merged = SbomMerger.mergeFile(target, source, RESOURCE, Boms.HOST_PREFIX);

        assertThat(merged).isEqualTo(Boms.npmFixture().path("components").size());
        JsonNode written = Boms.MAPPER.readTree(target.toFile());
        assertThat(written).isEqualTo(SbomMerger.merge(Boms.mavenFixture(), Boms.npmFixture(), Boms.HOST_PREFIX));
    }

    @Test
    void leavesTheTargetFileUntouchedWhenTheMergeFails() throws IOException {
        String original = Boms.mavenFixture().toPrettyString();
        Path target = Files.writeString(tempDir.resolve("application.cdx.json"), original);
        Path source = uiNgxClasses(Boms.npmFixture().toString());

        assertThatThrownBy(() -> SbomMerger.mergeFile(target, source, RESOURCE, "pkg:maven/org.thingsboard/missing@"))
                .isInstanceOf(SbomMergeException.class);

        assertThat(Files.readString(target)).isEqualTo(original);
    }

    @Test
    void leavesTheTargetFileUntouchedWhenTheResourceIsMissing() throws IOException {
        String original = Boms.mavenFixture().toPrettyString();
        Path target = Files.writeString(tempDir.resolve("application.cdx.json"), original);

        assertThatThrownBy(() -> SbomMerger.mergeFile(target, tempDir, RESOURCE, Boms.HOST_PREFIX))
                .isInstanceOf(SbomMergeException.class)
                .hasMessageContaining(RESOURCE + " not found");

        assertThat(Files.readString(target)).isEqualTo(original);
    }

    @Test
    void failsWhenTheTargetFileDoesNotExist() throws IOException {
        Path target = tempDir.resolve("application.cdx.json");
        Path source = uiNgxClasses(Boms.npmFixture().toString());

        assertThatThrownBy(() -> SbomMerger.mergeFile(target, source, RESOURCE, Boms.HOST_PREFIX))
                .isInstanceOf(SbomMergeException.class)
                .hasMessageContaining("SBOM file " + target + " does not exist");
    }

    private Path uiNgxClasses(String bom) throws IOException {
        Path classes = tempDir.resolve("ui-ngx-classes");
        Path file = classes.resolve(RESOURCE);
        Files.createDirectories(file.getParent());
        Files.writeString(file, bom);
        return classes;
    }

}
