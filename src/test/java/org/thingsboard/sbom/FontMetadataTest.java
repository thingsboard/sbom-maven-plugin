// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
package org.thingsboard.sbom;

import org.apache.fontbox.ttf.NameRecord;
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
import java.util.TreeMap;

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
    void supportsOfl10ApacheMitUbuntuLicenseResolverAndDirectSpdx() {
        byte[] ofl10 = syntheticTtf(Map.of(
                1, "Icons",
                5, "Version 1.0 (2024)\nextra",
                13, "Licensed under the SIL Open Font License, Version 1.0.",
                14, "http://scripts.sil.org/OFL"
        ));
        FontMetadata meta = FontMetadata.parse(ofl10, "Icons.ttf");
        assertThat(meta.version()).isEqualTo("1.0 (2024) extra");
        assertThat(meta.identifyLicense("Icons.ttf", Map.of())).isEqualTo("OFL-1.0");

        assertThat(new FontMetadata("F", "1.0", "", "Apache License, Version 2.0", "").identifyLicense("f.ttf", Map.of()))
                .isEqualTo("Apache-2.0");
        assertThat(new FontMetadata("F", "1.0", "", "The MIT License", "").identifyLicense("f.ttf", Map.of()))
                .isEqualTo("MIT");
        assertThat(new FontMetadata("F", "1.0", "", "Ubuntu Font Licence 1.0", "").identifyLicense("f.ttf", Map.of()))
                .isEqualTo("Ubuntu-font-1.0");
        assertThat(new FontMetadata("F", "1.0", "", "BSD-3-Clause", "").identifyLicense("f.ttf", Map.of()))
                .isEqualTo("BSD-3-Clause");
        // LicenseResolver resolves standard SPDX URLs when description is empty
        assertThat(new FontMetadata("F", "1.0", "", "", "https://www.apache.org/licenses/LICENSE-2.0").identifyLicense("f.ttf", Map.of()))
                .isEqualTo("Apache-2.0");
        // Does not falsely match substring "permit license"
        assertThatThrownBy(() -> new FontMetadata("F", "1.0", "", "Custom permit license", "").identifyLicense("f.ttf", Map.of()))
                .isInstanceOf(SbomException.class);
    }

    @Test
    void format1LanguageTagsDoNotMisclassifyAsWindowsEnglishOrUnicode() {
        int enUs = FontMetadata.priorityOf(NameRecord.PLATFORM_WINDOWS, NameRecord.ENCODING_WINDOWS_UNICODE_BMP, NameRecord.LANGUAGE_WINDOWS_EN_US);
        int enGb = FontMetadata.priorityOf(NameRecord.PLATFORM_WINDOWS, NameRecord.ENCODING_WINDOWS_UNICODE_BMP, 0x0809);
        int unicode = FontMetadata.priorityOf(NameRecord.PLATFORM_UNICODE, 3, 0);
        int macEn = FontMetadata.priorityOf(NameRecord.PLATFORM_MACINTOSH, NameRecord.ENCODING_MACINTOSH_ROMAN, NameRecord.LANGUAGE_MACINTOSH_ENGLISH);
        int format1Tag9Win = FontMetadata.priorityOf(NameRecord.PLATFORM_WINDOWS, NameRecord.ENCODING_WINDOWS_UNICODE_BMP, 0x8009);
        int format1Tag0Uni = FontMetadata.priorityOf(NameRecord.PLATFORM_UNICODE, 3, 0x8000);

        assertThat(enUs).isLessThan(enGb);
        assertThat(enGb).isLessThan(unicode);
        assertThat(unicode).isLessThan(macEn);
        assertThat(macEn).isLessThan(format1Tag9Win);
        assertThat(macEn).isLessThan(format1Tag0Uni);
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
    void rejectsInvalidFontBinary() {
        assertThatThrownBy(() -> FontMetadata.parse("not a font".getBytes(StandardCharsets.UTF_8), "bad.ttf"))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("Failed to read font bad.ttf");
    }

    /**
     * Builds a minimal valid TrueType font containing mandatory SFNT tables and the given {@code name} records.
     */
    static byte[] syntheticTtf(Map<Integer, String> names) {
        Map<String, byte[]> tables = new TreeMap<>();
        tables.put("glyf", new byte[4]);
        tables.put("head", minimalHeadTable());
        tables.put("hhea", minimalHheaTable());
        tables.put("hmtx", new byte[6]);
        tables.put("loca", new byte[6]);
        tables.put("maxp", minimalMaxpTable());
        tables.put("name", nameTable(names));

        int numTables = tables.size();
        int headerSize = 12 + numTables * 16;
        int totalSize = headerSize;
        for (byte[] table : tables.values()) {
            totalSize += padded(table.length);
        }

        ByteBuffer buf = ByteBuffer.allocate(totalSize).order(ByteOrder.BIG_ENDIAN);
        buf.putInt(0x00010000);
        buf.putShort((short) numTables);
        buf.putShort((short) 64);
        buf.putShort((short) 2);
        buf.putShort((short) 0);

        int offset = headerSize;
        for (Map.Entry<String, byte[]> entry : tables.entrySet()) {
            buf.put(entry.getKey().getBytes(StandardCharsets.US_ASCII));
            buf.putInt(0);
            buf.putInt(offset);
            buf.putInt(entry.getValue().length);
            offset += padded(entry.getValue().length);
        }
        for (byte[] table : tables.values()) {
            buf.put(table);
            int pad = padded(table.length) - table.length;
            for (int i = 0; i < pad; i++) {
                buf.put((byte) 0);
            }
        }
        return buf.array();
    }

    private static byte[] minimalHeadTable() {
        ByteBuffer head = ByteBuffer.allocate(54).order(ByteOrder.BIG_ENDIAN);
        head.putInt(0, 0x00010000); // majorVersion=1, minorVersion=0
        head.putInt(12, 0x5F0F3CF5); // magicNumber
        head.putShort(18, (short) 1000); // unitsPerEm
        return head.array();
    }

    private static byte[] minimalHheaTable() {
        ByteBuffer hhea = ByteBuffer.allocate(36).order(ByteOrder.BIG_ENDIAN);
        hhea.putShort(34, (short) 1); // numberOfHMetrics
        return hhea.array();
    }

    private static byte[] minimalMaxpTable() {
        ByteBuffer maxp = ByteBuffer.allocate(6).order(ByteOrder.BIG_ENDIAN);
        maxp.putInt(0, 0x00005000); // version 0.5
        maxp.putShort(4, (short) 2); // numGlyphs
        return maxp.array();
    }

    private static byte[] nameTable(Map<Integer, String> names) {
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
        ByteBuffer buf = ByteBuffer.allocate(stringStorageOffset + strings.size()).order(ByteOrder.BIG_ENDIAN);
        buf.putShort((short) 0);
        buf.putShort((short) count);
        buf.putShort((short) stringStorageOffset);
        for (Map.Entry<Integer, byte[]> entry : encoded.entrySet()) {
            buf.putShort((short) NameRecord.PLATFORM_WINDOWS);
            buf.putShort((short) NameRecord.ENCODING_WINDOWS_UNICODE_BMP);
            buf.putShort((short) NameRecord.LANGUAGE_WINDOWS_EN_US);
            buf.putShort((short) (int) entry.getKey());
            buf.putShort((short) entry.getValue().length);
            buf.putShort((short) (int) offsets.get(entry.getKey()));
        }
        buf.put(strings.toByteArray());
        return buf.array();
    }

    private static int padded(int length) {
        return (length + 3) & ~3;
    }
}
