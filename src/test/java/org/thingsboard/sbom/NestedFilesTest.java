// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
package org.thingsboard.sbom;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class NestedFilesTest {

    private static final String FONT = "fonts/roboto/Roboto-Regular.ttf";
    private static final String FONT_BYTES = "font bytes";

    @TempDir
    Path dir;

    @Test
    void checksEveryLocatedFileAtAnyDepth() throws IOException {
        JsonNode sbom = sbom("""
                {"components": [
                  {"bom-ref": "roboto", "name": "Roboto", "components": [
                    {"type": "file", "bom-ref": "regular", "name": "Roboto-Regular.ttf",
                     "hashes": [{"alg": "SHA-256", "content": "%s"}, {"alg": "SHA-1", "content": "%s"}],
                     "evidence": {"occurrences": [{"location": "%s"}]}}]},
                  {"bom-ref": "echarts", "name": "echarts", "hashes": [{"alg": "SHA-256", "content": "00"}]}]}
                """.formatted(hash("SHA-256", FONT_BYTES), hash("SHA-1", FONT_BYTES).toUpperCase(), FONT));

        assertThat(NestedFiles.check(library(), "org.example:report", sbom)).isEqualTo(1);
    }

    @Test
    void anSbomWithoutLocationsIsNotChecked() throws IOException {
        JsonNode sbom = sbom("""
                {"components": [{"bom-ref": "echarts", "name": "echarts", "hashes": [{"alg": "SHA-256", "content": "00"}]}]}
                """);

        assertThat(NestedFiles.check(dir.resolve("missing.jar"), "org.example:ui", sbom)).isZero();
    }

    @Test
    void theOccurrencesOfAComponentThatIsNotAFileAreNotChecked() throws IOException {
        JsonNode sbom = sbom("""
                {"components": [{"type": "library", "bom-ref": "lodash", "name": "lodash",
                  "evidence": {"occurrences": [{"location": "src/app/main.ts", "line": 12}]}}]}
                """);

        assertThat(NestedFiles.check(dir.resolve("missing.jar"), "org.example:ui", sbom)).isZero();
    }

    @Test
    void failsWhenTheFileHasOtherContent() throws IOException {
        JsonNode sbom = located("""
                "hashes": [{"alg": "SHA-256", "content": "%s"}],""".formatted(hash("SHA-256", "other bytes")), FONT);

        assertThatThrownBy(() -> NestedFiles.check(library(), "org.example:report", sbom))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("The SHA-256 of " + FONT + " in org.example:report is " + hash("SHA-256", FONT_BYTES))
                .hasMessageContaining("its SBOM gives " + hash("SHA-256", "other bytes") + " for regular");
    }

    @Test
    void failsWhenTheLibraryHasNoSuchFile() throws IOException {
        JsonNode sbom = located("", "fonts/roboto/Roboto-Bold.ttf");

        assertThatThrownBy(() -> NestedFiles.check(library(), "org.example:report", sbom))
                .isInstanceOf(SbomException.class)
                .hasMessage("The SBOM of org.example:report places regular at fonts/roboto/Roboto-Bold.ttf, which is not a file of the library");
    }

    @Test
    void failsWhenTheLocationIsADirectory() throws IOException {
        JsonNode sbom = located("", "fonts/roboto/");

        assertThatThrownBy(() -> NestedFiles.check(library(), "org.example:report", sbom))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("which is not a file of the library");
    }

    @Test
    void failsOnAHashThatCannotBeChecked() throws IOException {
        JsonNode sbom = located("""
                "hashes": [{"alg": "BLAKE3", "content": "00"}],""", FONT);

        assertThatThrownBy(() -> NestedFiles.check(library(), "org.example:report", sbom))
                .isInstanceOf(SbomException.class)
                .hasMessageStartingWith("The SBOM of org.example:report gives a BLAKE3 hash for regular, which cannot be checked");
    }

    private JsonNode located(String hashes, String location) throws IOException {
        return sbom("""
                {"components": [{"type": "file", "bom-ref": "regular", "name": "Roboto-Regular.ttf", %s
                  "evidence": {"occurrences": [{"location": "%s"}]}}]}
                """.formatted(hashes, location));
    }

    private Path library() throws IOException {
        Path jar = dir.resolve("report.jar");
        try (OutputStream file = Files.newOutputStream(jar); ZipOutputStream zip = new ZipOutputStream(file)) {
            zip.putNextEntry(new ZipEntry("fonts/roboto/"));
            zip.closeEntry();
            zip.putNextEntry(new ZipEntry(FONT));
            zip.write(FONT_BYTES.getBytes(StandardCharsets.UTF_8));
            zip.closeEntry();
        }
        return jar;
    }

    private static JsonNode sbom(String json) throws IOException {
        return SbomFiles.MAPPER.readTree(json);
    }

    private static String hash(String algorithm, String content) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance(algorithm).digest(content.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
