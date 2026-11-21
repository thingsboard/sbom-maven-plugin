// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
package org.thingsboard.sbom;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.cyclonedx.model.Component;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SbomFontsTest {

    @TempDir
    Path dir;

    @Test
    void groupsFontVariantsChecksFilesInJarAndMergesIntoApplicationSbom() throws IOException {
        Path classes = dir.resolve("classes");
        Path robotoDir = Files.createDirectories(classes.resolve("fonts/roboto"));
        Path monoDir = Files.createDirectories(classes.resolve("fonts/monospace"));

        byte[] robotoRegular = FontMetadataTest.syntheticTtf(Map.of(
                0, "Copyright 2011 The Roboto Project Authors",
                1, "Roboto",
                5, "Version 3.009; 2024",
                13, "This Font Software is licensed under the SIL Open Font License, Version 1.1."
        ));
        byte[] robotoMedium = FontMetadataTest.syntheticTtf(Map.of(
                0, "Copyright 2011 The Roboto Project Authors ",
                1, "Roboto Medium",
                5, "Version 3.009; 2024",
                13, "This Font Software is licensed under the SIL Open Font License, Version 1.1.",
                16, "Roboto"
        ));
        byte[] dejavu = FontMetadataTest.syntheticTtf(Map.of(
                0, "Copyright (c) 2003 by Bitstream, Inc.",
                1, "DejaVu Sans Mono",
                5, "Version 2.37",
                13, "Bitstream Vera Fonts Copyright"
        ));

        Files.write(robotoDir.resolve("Roboto-Regular.ttf"), robotoRegular);
        Files.write(robotoDir.resolve("Roboto-Medium.ttf"), robotoMedium);
        Files.write(monoDir.resolve("DejaVuSansMono.ttf"), dejavu);

        Component tool = new Component();
        tool.setType(Component.Type.LIBRARY);
        tool.setGroup("org.thingsboard");
        tool.setName("sbom-maven-plugin");
        tool.setVersion("3.2.1-SNAPSHOT");

        SbomFonts.Result result = SbomFonts.describe(
                "org.thingsboard.common", "report", "4.4.1-SNAPSHOT",
                tool, classes, "fonts", Map.of(), true
        );
        // Deterministic serial number across repeated runs
        SbomFonts.Result again = SbomFonts.describe(
                "org.thingsboard.common", "report", "4.4.1-SNAPSHOT",
                tool, classes, "fonts", Map.of(), true
        );
        assertThat(result.bom()).isEqualTo(again.bom());

        assertThat(result.families()).isEqualTo(2);
        assertThat(result.files()).isEqualTo(3);

        JsonNode components = result.bom().path("components");
        assertThat(components).hasSize(2);
        assertThat(components.get(0).path("name").asText()).isEqualTo("DejaVu Sans Mono");
        assertThat(components.get(0).path("licenses").get(0).path("expression").asText()).isEqualTo("Bitstream-Vera");
        assertThat(components.get(1).path("name").asText()).isEqualTo("Roboto");
        assertThat(components.get(1).path("version").asText()).isEqualTo("3.009");
        assertThat(components.get(1).path("copyright").asText()).isEqualTo("Copyright 2011 The Roboto Project Authors");
        assertThat(components.get(1).path("components")).hasSize(2);

        // Verify NestedFiles checks all 3 files against a jar containing them
        Path jar = dir.resolve("report.jar");
        try (OutputStream out = Files.newOutputStream(jar); ZipOutputStream zip = new ZipOutputStream(out)) {
            putEntry(zip, "fonts/roboto/Roboto-Regular.ttf", robotoRegular);
            putEntry(zip, "fonts/roboto/Roboto-Medium.ttf", robotoMedium);
            putEntry(zip, "fonts/monospace/DejaVuSansMono.ttf", dejavu);
        }
        assertThat(NestedFiles.check(jar, "org.thingsboard.common:report", result.bom())).isEqualTo(3);

        // Verify SbomMerger merges the font SBOM cleanly into an application SBOM
        ObjectNode target = Boms.mavenFixture().deepCopy();
        String hostPurl = "pkg:maven/org.thingsboard.common/report@4.4.1-SNAPSHOT?type=jar";
        ObjectNode host = target.withArrayProperty("components").addObject();
        host.put("type", "library").put("group", "org.thingsboard.common").put("name", "report")
                .put("version", "4.4.1-SNAPSHOT").put("bom-ref", hostPurl).put("purl", hostPurl);
        target.withArrayProperty("dependencies").addObject().put("ref", hostPurl);
        String rootRef = target.path("metadata").path("component").path("bom-ref").asText();
        for (JsonNode dep : target.path("dependencies")) {
            if (rootRef.equals(dep.path("ref").asText())) {
                ((ObjectNode) dep).withArrayProperty("dependsOn").add(hostPurl);
            }
        }
        ObjectNode merged = SbomMerger.merge(target, result.bom(), "pkg:maven/org.thingsboard.common/report@");
        assertThat(SbomChecks.componentRefs(merged)).contains(
                components.get(0).path("bom-ref").asText(),
                components.get(1).path("bom-ref").asText()
        );
    }

    @Test
    void handlesSpacedVersionsSpdxPlusOverridesDuplicateFilenamesAndLibraryScoping() throws IOException {
        Path classes = Files.createDirectories(dir.resolve("edge"));
        Path sub = Files.createDirectories(classes.resolve("A"));
        byte[] fontA = FontMetadataTest.syntheticTtf(Map.of(
                0, "Copyright 2024 Example",
                1, "My Font",
                5, "Version 1.0 (2024)"
        ));
        // Same filename in subdir and root (used to collide when childRef dropped directory)
        Files.write(sub.resolve("Regular.ttf"), fontA);
        Files.write(classes.resolve("Regular.ttf"), fontA);

        SbomFonts.Result lib1 = SbomFonts.describe(
                "org.example", "lib-one", "1.0", null, classes, ".", Map.of("My Font", "MIT+"), false
        );
        SbomFonts.Result lib2 = SbomFonts.describe(
                "org.example", "lib-two", "1.0", null, classes, "", Map.of("My Font", "MIT OR Apache-2.0"), false
        );

        JsonNode c1 = lib1.bom().path("components").get(0);
        JsonNode c2 = lib2.bom().path("components").get(0);
        // PURL properly percent-encodes spaces in version
        assertThat(c1.path("purl").asText()).isEqualTo("pkg:generic/my-font@1.0%20%282024%29");
        assertThat(c1.path("licenses").get(0).path("expression").asText()).isEqualTo("MIT+");
        assertThat(c1.path("components")).hasSize(2);
        // Locations have no leading "./"
        assertThat(c1.path("components").get(0).path("evidence").path("occurrences").get(0).path("location").asText())
                .isEqualTo("A/Regular.ttf");
        assertThat(c1.path("components").get(1).path("evidence").path("occurrences").get(0).path("location").asText())
                .isEqualTo("Regular.ttf");
        // Scoped bom-refs never collide across different libraries
        assertThat(c1.path("bom-ref").asText()).isNotEqualTo(c2.path("bom-ref").asText());
    }

    @Test
    void rejectsEscapingFontDirectoryAndEmptyDirectory() throws IOException {
        Path classes = Files.createDirectories(dir.resolve("empty/fonts"));
        assertThatThrownBy(() -> SbomFonts.describe("org.example", "report", "1.0", null, classes.getParent(), "fonts", Map.of(), false))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("No .ttf or .otf font files found");
        assertThatThrownBy(() -> SbomFonts.describe("org.example", "report", "1.0", null, classes.getParent(), "../outside", Map.of(), false))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("must be inside resources directory");
    }

    private static void putEntry(ZipOutputStream zip, String name, byte[] bytes) throws IOException {
        zip.putNextEntry(new ZipEntry(name));
        zip.write(bytes);
        zip.closeEntry();
    }
}
