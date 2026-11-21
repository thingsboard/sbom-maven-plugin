// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
package org.thingsboard.sbom;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class FontMetadataTest {

    @TempDir
    Path dir;

    @Test
    void readsTypographicFamilyVersionCopyrightAndIdentifiesOflAndBitstreamVera() throws IOException {
        byte[] robotoMedium = syntheticTtf(Map.of(
                0, "Copyright 2011 The Roboto Project Authors \r\n",
                1, "Roboto Medium",
                5, "Version 3.009; 2024",
                13, "This Font Software is licensed under the SIL Open Font License, Version 1.1.",
                14, "https://openfontlicense.org",
                16, "Roboto"
        ));
        Path robotoPath = Files.write(dir.resolve("Roboto-Medium.ttf"), robotoMedium);

        FontMetadata meta = FontMetadata.read(robotoPath);
        assertThat(meta.family()).isEqualTo("Roboto");
        assertThat(meta.version()).isEqualTo("3.009");
        assertThat(meta.copyright()).isEqualTo("Copyright 2011 The Roboto Project Authors");
        assertThat(meta.identifyLicense("fonts/roboto/Roboto-Medium.ttf", Map.of())).isEqualTo("OFL-1.1");

        byte[] dejavu = syntheticTtf(Map.of(
                0, "Copyright (c) 2003 by Bitstream, Inc. All Rights Reserved.\nDejaVu changes are in public domain",
                1, "DejaVu Sans Mono",
                5, "Version 2.37",
                13, "Fonts are (c) Bitstream (see below). Bitstream Vera Fonts Copyright",
                14, "http://dejavu.sourceforge.net/wiki/index.php/License"
        ));

        FontMetadata dejavuMeta = FontMetadata.parse(dejavu, "fonts/DejaVuSansMono.ttf");
        assertThat(dejavuMeta.family()).isEqualTo("DejaVu Sans Mono");
        assertThat(dejavuMeta.version()).isEqualTo("2.37");
        assertThat(dejavuMeta.identifyLicense("fonts/DejaVuSansMono.ttf", Map.of())).isEqualTo("Bitstream-Vera");
    }

    @Test
    void supportsOtfHeaderAndDistinguishesOfl10ApacheMitUbuntuAndDirectSpdx() {
        byte[] otf = syntheticFont(0x4F54544F, Map.of(
                1, "Icons",
                5, "Version 1.0 (2024)\nextra",
                13, "Licensed under the SIL Open Font License, Version 1.0.",
                14, "http://scripts.sil.org/OFL"
        ));
        FontMetadata otfMeta = FontMetadata.parse(otf, "Icons.otf");
        assertThat(otfMeta.version()).isEqualTo("1.0 (2024) extra");
        assertThat(otfMeta.identifyLicense("Icons.otf", Map.of())).isEqualTo("OFL-1.0");

        assertThat(new FontMetadata("F", "1.0", "", "Apache License, Version 2.0", "").identifyLicense("f.ttf", Map.of()))
                .isEqualTo("Apache-2.0");
        assertThat(new FontMetadata("F", "1.0", "", "The MIT License", "").identifyLicense("f.ttf", Map.of()))
                .isEqualTo("MIT");
        assertThat(new FontMetadata("F", "1.0", "", "Ubuntu Font Licence 1.0", "").identifyLicense("f.ttf", Map.of()))
                .isEqualTo("Ubuntu-font-1.0");
        assertThat(new FontMetadata("F", "1.0", "", "BSD-3-Clause", "").identifyLicense("f.ttf", Map.of()))
                .isEqualTo("BSD-3-Clause");
        // Does not falsely match substring "permit license"
        assertThatThrownBy(() -> new FontMetadata("F", "1.0", "", "Custom permit license", "").identifyLicense("f.ttf", Map.of()))
                .isInstanceOf(SbomException.class);
    }

    @Test
    void failsClosedOnUnknownLicenseUnlessOverriddenWithValidSpdx() {
        byte[] unknown = syntheticTtf(Map.of(
                0, "Copyright 2024 Example Foundry",
                1, "Custom Font",
                5, "Version 1.0",
                13, "All rights reserved. Proprietary commercial font."
        ));

        FontMetadata meta = FontMetadata.parse(unknown, "fonts/Custom.ttf");
        assertThatThrownBy(() -> meta.identifyLicense("fonts/Custom.ttf", Map.of()))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("Cannot determine an SPDX license for font fonts/Custom.ttf");

        Map<String, String> byPath = FontLicense.toMap(List.of(new FontLicense("fonts/Custom.ttf", "Apache-2.0")));
        assertThat(meta.identifyLicense("fonts/Custom.ttf", byPath)).isEqualTo("Apache-2.0");

        Map<String, String> byFamily = FontLicense.toMap(List.of(new FontLicense("Custom Font", "MIT OR Apache-2.0")));
        assertThat(meta.identifyLicense("fonts/Custom.ttf", byFamily)).isEqualTo("MIT OR Apache-2.0");

        assertThatThrownBy(() -> FontLicense.toMap(List.of(new FontLicense("Custom Font", "Not A License"))))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("not a valid SPDX license expression");
        assertThatThrownBy(() -> FontLicense.toMap(List.of(new FontLicense(" ", "MIT"))))
                .isInstanceOf(SbomException.class);
    }

    @Test
    void rejectsInvalidFontBinaryAndOutOfBoundsNameTable() {
        assertThatThrownBy(() -> FontMetadata.parse("not a font".getBytes(StandardCharsets.UTF_8), "bad.ttf"))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("not a valid TrueType/OpenType");

        // Truncated name table offset pointing past EOF
        ByteBuffer bad = ByteBuffer.allocate(28).order(ByteOrder.BIG_ENDIAN);
        bad.putInt(0x00010000).putShort((short) 1).putShort((short) 16).putShort((short) 0).putShort((short) 0);
        bad.putInt(0x6E616D65).putInt(0).putInt(999).putInt(100);
        assertThatThrownBy(() -> FontMetadata.parse(bad.array(), "trunc.ttf"))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("no valid OpenType name table");
    }

    static byte[] syntheticTtf(Map<Integer, String> names) {
        return syntheticFont(0x00010000, names);
    }

    static byte[] syntheticFont(int sfntVersion, Map<Integer, String> names) {
        Map<Integer, byte[]> encoded = new LinkedHashMap<>();
        ByteArrayOutputStream strings = new ByteArrayOutputStream();
        Map<Integer, Integer> offsets = new LinkedHashMap<>();
        for (Map.Entry<Integer, String> entry : names.entrySet()) {
            byte[] bytes = entry.getValue().getBytes(StandardCharsets.UTF_16BE);
            offsets.put(entry.getKey(), strings.size());
            encoded.put(entry.getKey(), bytes);
            strings.writeBytes(bytes);
        }
        int count = encoded.size();
        int stringStorageOffset = 6 + count * 12;
        int nameTableLength = stringStorageOffset + strings.size();
        int nameTableOffset = 12 + 16;

        ByteBuffer buf = ByteBuffer.allocate(nameTableOffset + nameTableLength).order(ByteOrder.BIG_ENDIAN);
        buf.putInt(sfntVersion);
        buf.putShort((short) 1);
        buf.putShort((short) 16);
        buf.putShort((short) 0);
        buf.putShort((short) 0);
        buf.putInt(0x6E616D65);
        buf.putInt(0);
        buf.putInt(nameTableOffset);
        buf.putInt(nameTableLength);
        buf.putShort((short) 0);
        buf.putShort((short) count);
        buf.putShort((short) stringStorageOffset);
        for (Map.Entry<Integer, byte[]> entry : encoded.entrySet()) {
            buf.putShort((short) 3);      // Windows
            buf.putShort((short) 1);      // Unicode BMP
            buf.putShort((short) 0x0409); // English US
            buf.putShort((short) (int) entry.getKey());
            buf.putShort((short) entry.getValue().length);
            buf.putShort((short) (int) offsets.get(entry.getKey()));
        }
        buf.put(strings.toByteArray());
        return buf.array();
    }
}
