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
import java.util.ArrayList;
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
    void readsBitmapColorTtfWithoutOutlineTablesAndOpenTypeCffOtf() {
        // Mimics color/bitmap TTF fonts (e.g. NotoColorEmoji.ttf with CBDT/CBLC) that have no loca or glyf tables.
        Map<String, byte[]> bitmapTables = new TreeMap<>();
        bitmapTables.put("CBDT", new byte[16]);
        bitmapTables.put("CBLC", new byte[16]);
        bitmapTables.put("name", nameTableFormat0(List.of(
                winEnUs(0, "Copyright 2024 Google"),
                winEnUs(1, "Noto Color Emoji"),
                winEnUs(5, "Version 2.047"),
                winEnUs(13, "SIL Open Font License, Version 1.1")
        )));
        FontMetadata emoji = FontMetadata.parse(sfnt(0x00010000, bitmapTables), "NotoColorEmoji.ttf");
        assertThat(emoji.family()).isEqualTo("Noto Color Emoji");
        assertThat(emoji.version()).isEqualTo("2.047");
        assertThat(emoji.identifyLicense("NotoColorEmoji.ttf", Map.of())).isEqualTo("OFL-1.1");

        // OpenType CFF (.otf) header 'OTTO'
        Map<String, byte[]> otfTables = new TreeMap<>();
        otfTables.put("CFF ", new byte[8]);
        otfTables.put("name", nameTableFormat0(List.of(
                winEnUs(1, "Source Sans 3"),
                winEnUs(5, "Version 3.052"),
                winEnUs(14, "https://openfontlicense.org")
        )));
        FontMetadata otf = FontMetadata.parse(sfnt(0x4F54544F, otfTables), "SourceSans3.otf");
        assertThat(otf.family()).isEqualTo("Source Sans 3");
        assertThat(otf.version()).isEqualTo("3.052");
        assertThat(otf.identifyLicense("SourceSans3.otf", Map.of())).isEqualTo("OFL-1.1");
    }

    @Test
    void readsOpenTypeFormat1NameTableHonoringStorageOffsetAndLanguageTagPriority() {
        List<RawNameRecord> records = List.of(
                new RawNameRecord(FontMetadata.PLATFORM_WINDOWS, FontMetadata.ENCODING_WINDOWS_UNICODE_BMP, 0x8009, 1, "Wrong Tag Family"),
                new RawNameRecord(FontMetadata.PLATFORM_UNICODE, 3, 0x8000, 1, "Unicode Tag Family"),
                new RawNameRecord(FontMetadata.PLATFORM_MACINTOSH, FontMetadata.ENCODING_MAC_ROMAN, FontMetadata.LANGUAGE_MAC_ENGLISH, 1, "Mac English Family"),
                winEnUs(0, "Copyright 2024 Format 1 Foundry"),
                winEnUs(1, "Roboto"),
                winEnUs(5, "Version 3.009"),
                winEnUs(13, "Apache License, Version 2.0")
        );
        byte[] font = sfnt(0x00010000, Map.of("name", nameTableFormat1(records, List.of("en-US", "fr-FR"))));

        FontMetadata meta = FontMetadata.parse(font, "Format1.ttf");
        assertThat(meta.family()).isEqualTo("Roboto");
        assertThat(meta.version()).isEqualTo("3.009");
        assertThat(meta.copyright()).isEqualTo("Copyright 2024 Format 1 Foundry");
        assertThat(meta.identifyLicense("Format1.ttf", Map.of())).isEqualTo("Apache-2.0");

        // When only Mac English and Format 1 language-tag records exist, Mac English wins over Format 1 tags.
        byte[] macVsTag = sfnt(0x00010000, Map.of("name", nameTableFormat1(List.of(
                new RawNameRecord(FontMetadata.PLATFORM_WINDOWS, FontMetadata.ENCODING_WINDOWS_UNICODE_BMP, 0x8009, 1, "Tag Family"),
                new RawNameRecord(FontMetadata.PLATFORM_MACINTOSH, FontMetadata.ENCODING_MAC_ROMAN, FontMetadata.LANGUAGE_MAC_ENGLISH, 1, "Mac Family")
        ), List.of("en-US"))));
        assertThat(FontMetadata.parse(macVsTag, "MacVsTag.ttf").family()).isEqualTo("Mac Family");

        // MacRoman non-ASCII bytes (>= 0x80) decode cleanly rather than as ISO-8859-1 mojibake
        byte[] macOnly = sfnt(0x00010000, Map.of("name", nameTableFormat0(List.of(
                new RawNameRecord(FontMetadata.PLATFORM_MACINTOSH, FontMetadata.ENCODING_MAC_ROMAN,
                        FontMetadata.LANGUAGE_MAC_ENGLISH, 0, "Copyright \u00A9 2024 Foundr\u00E9\u00AE"),
                new RawNameRecord(FontMetadata.PLATFORM_MACINTOSH, FontMetadata.ENCODING_MAC_ROMAN,
                        FontMetadata.LANGUAGE_MAC_ENGLISH, 1, "Caf\u00E9 Sans")
        ))));
        FontMetadata macMeta = FontMetadata.parse(macOnly, "CafeSans.ttf");
        assertThat(macMeta.family()).isEqualTo("Caf\u00E9 Sans");
        assertThat(macMeta.copyright()).isEqualTo("Copyright \u00A9 2024 Foundr\u00E9\u00AE");
    }

    @Test
    void supportsOfl10ApacheMitUbuntuLicenseResolverUrlVariantsAndDirectSpdx() {
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
        // LicenseResolver + URL fallback variants when description is empty
        assertThat(new FontMetadata("F", "1.0", "", "", "https://www.apache.org/licenses/LICENSE-2.0").identifyLicense("f.ttf", Map.of()))
                .isEqualTo("Apache-2.0");
        assertThat(new FontMetadata("F", "1.0", "", "", "http://www.apache.org/licenses/LICENSE-2.0.html").identifyLicense("f.ttf", Map.of()))
                .isEqualTo("Apache-2.0");
        assertThat(new FontMetadata("F", "1.0", "", "", "https://www.apache.org/licenses/LICENSE-2.0.txt").identifyLicense("f.ttf", Map.of()))
                .isEqualTo("Apache-2.0");
        assertThat(new FontMetadata("F", "1.0", "", "", "https://www.apache.org/licenses/LICENSE-2.0/").identifyLicense("f.ttf", Map.of()))
                .isEqualTo("Apache-2.0");
        assertThat(new FontMetadata("F", "1.0", "", "", "https://opensource.org/license/MIT/").identifyLicense("f.ttf", Map.of()))
                .isEqualTo("MIT");
        // Preserves SPDX licenses whose canonical seeAlso URL ends with '/'
        assertThat(new FontMetadata("F", "1.0", "", "", "https://www.mozilla.org/MPL/2.0/").identifyLicense("f.ttf", Map.of()))
                .isEqualTo("MPL-2.0");
        assertThat(new FontMetadata("F", "1.0", "", "", "https://www.mozilla.org/MPL/2.0").identifyLicense("f.ttf", Map.of()))
                .isEqualTo("MPL-2.0");
        // Does not falsely match substring "permit license"
        assertThatThrownBy(() -> new FontMetadata("F", "1.0", "", "Custom permit license", "").identifyLicense("f.ttf", Map.of()))
                .isInstanceOf(SbomException.class);
    }

    @Test
    void normalizesVersionStrings() {
        assertThat(FontMetadata.normalizeVersion(null)).isEmpty();
        assertThat(FontMetadata.normalizeVersion("   ")).isEmpty();
        assertThat(FontMetadata.normalizeVersion("Version  ")).isEmpty();
        assertThat(FontMetadata.normalizeVersion("Version Version 1.2")).isEqualTo("1.2");
        assertThat(FontMetadata.normalizeVersion("Version 3.009; 2024")).isEqualTo("3.009");
        assertThat(FontMetadata.normalizeVersion("VersionVersion")).isEqualTo("VersionVersion");
    }

    @Test
    void format1LanguageTagsDoNotMisclassifyAsWindowsEnglishOrUnicode() {
        int enUs = FontMetadata.priorityOf(FontMetadata.PLATFORM_WINDOWS, FontMetadata.ENCODING_WINDOWS_UNICODE_BMP, FontMetadata.LANGUAGE_WINDOWS_EN_US);
        int enGb = FontMetadata.priorityOf(FontMetadata.PLATFORM_WINDOWS, FontMetadata.ENCODING_WINDOWS_UNICODE_BMP, 0x0809);
        int unicode = FontMetadata.priorityOf(FontMetadata.PLATFORM_UNICODE, 3, 0);
        int macEn = FontMetadata.priorityOf(FontMetadata.PLATFORM_MACINTOSH, FontMetadata.ENCODING_MAC_ROMAN, FontMetadata.LANGUAGE_MAC_ENGLISH);
        int format1Tag9Win = FontMetadata.priorityOf(FontMetadata.PLATFORM_WINDOWS, FontMetadata.ENCODING_WINDOWS_UNICODE_BMP, 0x8009);
        int format1Tag0Uni = FontMetadata.priorityOf(FontMetadata.PLATFORM_UNICODE, 3, 0x8000);

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
     * Builds a minimal SFNT TrueType font containing a Format 0 {@code name} table with the given Windows EN-US strings.
     */
    static byte[] syntheticTtf(Map<Integer, String> names) {
        List<RawNameRecord> records = new ArrayList<>();
        for (Map.Entry<Integer, String> entry : new LinkedHashMap<>(names).entrySet()) {
            records.add(winEnUs(entry.getKey(), entry.getValue()));
        }
        return sfnt(0x00010000, Map.of("name", nameTableFormat0(records)));
    }

    private static RawNameRecord winEnUs(int nameId, String value) {
        return new RawNameRecord(FontMetadata.PLATFORM_WINDOWS, FontMetadata.ENCODING_WINDOWS_UNICODE_BMP,
                FontMetadata.LANGUAGE_WINDOWS_EN_US, nameId, value);
    }

    private static byte[] sfnt(int sfntVersion, Map<String, byte[]> tablesInput) {
        Map<String, byte[]> tables = new TreeMap<>(tablesInput);
        int numTables = tables.size();
        int headerSize = 12 + numTables * 16;
        int totalSize = headerSize;
        for (byte[] table : tables.values()) {
            totalSize += padded(table.length);
        }

        ByteBuffer buf = ByteBuffer.allocate(totalSize).order(ByteOrder.BIG_ENDIAN);
        buf.putInt(sfntVersion);
        buf.putShort((short) numTables);
        buf.putShort((short) 0);
        buf.putShort((short) 0);
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

    private static byte[] nameTableFormat0(List<RawNameRecord> records) {
        return nameTable(0, records, List.of());
    }

    private static byte[] nameTableFormat1(List<RawNameRecord> records, List<String> langTags) {
        return nameTable(1, records, langTags);
    }

    private static byte[] nameTable(int format, List<RawNameRecord> records, List<String> langTags) {
        ByteArrayOutputStream strings = new ByteArrayOutputStream();
        List<int[]> encoded = new ArrayList<>();
        for (RawNameRecord rec : records) {
            byte[] bytes = rec.platformId == FontMetadata.PLATFORM_MACINTOSH
                    ? rec.value.getBytes(FontMetadata.MAC_ROMAN)
                    : rec.value.getBytes(StandardCharsets.UTF_16BE);
            int off = strings.size();
            strings.writeBytes(bytes);
            encoded.add(new int[]{rec.platformId, rec.encodingId, rec.languageId, rec.nameId, bytes.length, off});
        }
        List<int[]> encodedTags = new ArrayList<>();
        for (String tag : langTags) {
            byte[] bytes = tag.getBytes(StandardCharsets.UTF_16BE);
            int off = strings.size();
            strings.writeBytes(bytes);
            encodedTags.add(new int[]{bytes.length, off});
        }

        int langSectionBytes = format == 1 ? 2 + encodedTags.size() * 4 : 0;
        int storageOffset = 6 + encoded.size() * 12 + langSectionBytes;
        ByteBuffer buf = ByteBuffer.allocate(storageOffset + strings.size()).order(ByteOrder.BIG_ENDIAN);
        buf.putShort((short) format);
        buf.putShort((short) encoded.size());
        buf.putShort((short) storageOffset);
        for (int[] rec : encoded) {
            for (int field : rec) {
                buf.putShort((short) field);
            }
        }
        if (format == 1) {
            buf.putShort((short) encodedTags.size());
            for (int[] tag : encodedTags) {
                buf.putShort((short) tag[0]);
                buf.putShort((short) tag[1]);
            }
        }
        buf.put(strings.toByteArray());
        return buf.array();
    }

    private static int padded(int length) {
        return (length + 3) & ~3;
    }

    private record RawNameRecord(int platformId, int encodingId, int languageId, int nameId, String value) {}
}
