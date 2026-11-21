// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
package org.thingsboard.sbom;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.charset.UnsupportedCharsetException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static org.thingsboard.sbom.SbomChecks.check;

/**
 * Reads licensing and version metadata from the OpenType/TrueType {@code name} table of a {@code .ttf} or {@code .otf}
 * font file.
 */
record FontMetadata(String family, String version, String copyright, String licenseDescription, String licenseUrl) {

    private static final int SFNT_TRUETYPE = 0x00010000;
    private static final int SFNT_APPLE_TRUE = 0x74727565; // 'true'
    private static final int SFNT_OPENTYPE_CFF = 0x4F54544F; // 'OTTO'
    private static final int TABLE_NAME = 0x6E616D65; // 'name'

    private static final int NAME_COPYRIGHT = 0;
    private static final int NAME_FAMILY = 1;
    private static final int NAME_VERSION = 5;
    private static final int NAME_LICENSE = 13;
    private static final int NAME_LICENSE_URL = 14;
    private static final int NAME_TYPOGRAPHIC_FAMILY = 16;

    private static final int MAX_NAME_TABLE_BYTES = 4 * 1024 * 1024;
    private static final Charset MAC_ROMAN = macRomanCharset();

    private static final Pattern VERSION_PREFIX = Pattern.compile("^(?:version\\s+)+", Pattern.CASE_INSENSITIVE);
    private static final Pattern WHITESPACE = Pattern.compile("\\s+");
    private static final Pattern MIT_LICENSE_PHRASE = Pattern.compile("\\bthe mit license\\b|\\bmit license\\b");

    static FontMetadata read(Path file) {
        try (SeekableByteChannel channel = Files.newByteChannel(file, StandardOpenOption.READ)) {
            long fileSize = channel.size();
            check(fileSize >= 12, "Font " + file + " is not a valid TrueType/OpenType file (too short)");

            ByteBuffer header = readFully(channel, 0, 12);
            int sfntVersion = header.getInt(0);
            check(sfntVersion == SFNT_TRUETYPE || sfntVersion == SFNT_APPLE_TRUE || sfntVersion == SFNT_OPENTYPE_CFF,
                    "Font " + file + " is not a supported TrueType/OpenType file");

            int numTables = header.getShort(4) & 0xFFFF;
            long directoryBytes = (long) numTables * 16;
            check(12 + directoryBytes <= fileSize, "Font " + file + " has a truncated table directory");

            ByteBuffer directory = readFully(channel, 12, (int) directoryBytes);
            long nameOffset = -1;
            long nameLength = 0;
            for (int i = 0; i < numTables; i++) {
                int entry = i * 16;
                if (directory.getInt(entry) == TABLE_NAME) {
                    nameOffset = Integer.toUnsignedLong(directory.getInt(entry + 8));
                    nameLength = Integer.toUnsignedLong(directory.getInt(entry + 12));
                    break;
                }
            }
            check(nameOffset >= 0 && nameLength >= 6 && nameLength <= MAX_NAME_TABLE_BYTES && nameOffset + nameLength <= fileSize,
                    "Font " + file + " has no valid OpenType name table");

            ByteBuffer nameTable = readFully(channel, nameOffset, (int) nameLength);
            return parseNameTable(nameTable.array(), file.toString());
        } catch (IOException e) {
            throw new SbomException("Failed to read font " + file, e);
        }
    }

    static FontMetadata parse(byte[] data, String source) {
        check(data.length >= 12, "Font " + source + " is not a valid TrueType/OpenType file (too short)");
        ByteBuffer buf = ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN);
        int sfntVersion = buf.getInt(0);
        check(sfntVersion == SFNT_TRUETYPE || sfntVersion == SFNT_APPLE_TRUE || sfntVersion == SFNT_OPENTYPE_CFF,
                "Font " + source + " is not a supported TrueType/OpenType file");

        int numTables = buf.getShort(4) & 0xFFFF;
        check(12 + (long) numTables * 16 <= data.length, "Font " + source + " has a truncated table directory");

        long nameOffset = -1;
        long nameLength = 0;
        for (int i = 0; i < numTables; i++) {
            int entry = 12 + i * 16;
            if (buf.getInt(entry) == TABLE_NAME) {
                nameOffset = Integer.toUnsignedLong(buf.getInt(entry + 8));
                nameLength = Integer.toUnsignedLong(buf.getInt(entry + 12));
                break;
            }
        }
        check(nameOffset >= 0 && nameLength >= 6 && nameLength <= MAX_NAME_TABLE_BYTES && nameOffset + nameLength <= data.length,
                "Font " + source + " has no valid OpenType name table");

        byte[] table = new byte[(int) nameLength];
        System.arraycopy(data, (int) nameOffset, table, 0, (int) nameLength);
        return parseNameTable(table, source);
    }

    private static FontMetadata parseNameTable(byte[] table, String source) {
        ByteBuffer buf = ByteBuffer.wrap(table).order(ByteOrder.BIG_ENDIAN);
        int format = buf.getShort(0) & 0xFFFF;
        check(format == 0 || format == 1, "Font " + source + " has unsupported OpenType name table format " + format);

        int count = buf.getShort(2) & 0xFFFF;
        int storageOffset = buf.getShort(4) & 0xFFFF;
        long recordsEnd = 6L + (long) count * 12;
        check(recordsEnd <= table.length && storageOffset <= table.length,
                "Font " + source + " has a truncated OpenType name table");

        Map<Integer, String> langTags = format == 1 ? readLangTags(buf, table, (int) recordsEnd, storageOffset) : Map.of();
        Map<Integer, PrioritizedString> values = new HashMap<>();
        for (int i = 0; i < count; i++) {
            int record = 6 + i * 12;
            int platformId = buf.getShort(record) & 0xFFFF;
            int encodingId = buf.getShort(record + 2) & 0xFFFF;
            int languageId = buf.getShort(record + 4) & 0xFFFF;
            int nameId = buf.getShort(record + 6) & 0xFFFF;
            if (nameId != NAME_COPYRIGHT && nameId != NAME_FAMILY && nameId != NAME_VERSION
                    && nameId != NAME_LICENSE && nameId != NAME_LICENSE_URL && nameId != NAME_TYPOGRAPHIC_FAMILY) {
                continue;
            }
            int length = buf.getShort(record + 8) & 0xFFFF;
            int stringOffset = buf.getShort(record + 10) & 0xFFFF;
            long start = (long) storageOffset + stringOffset;
            if (start + length > table.length) {
                continue;
            }
            Charset charset = charsetFor(platformId, encodingId);
            if (charset == null) {
                continue;
            }
            String text = new String(table, (int) start, length, charset).trim();
            if (text.isEmpty()) {
                continue;
            }
            int priority = priorityOf(platformId, encodingId, languageId, langTags.get(languageId));
            values.merge(nameId, new PrioritizedString(priority, text),
                    (existing, incoming) -> incoming.priority < existing.priority ? incoming : existing);
        }

        String typographic = get(values, NAME_TYPOGRAPHIC_FAMILY);
        String family = !typographic.isEmpty() ? typographic : get(values, NAME_FAMILY);
        check(!family.isEmpty(), "Font " + source + " has no family name in its OpenType name table");

        return new FontMetadata(
                family,
                normalizeVersion(get(values, NAME_VERSION)),
                normalizeMultiline(get(values, NAME_COPYRIGHT)),
                normalizeMultiline(get(values, NAME_LICENSE)),
                get(values, NAME_LICENSE_URL)
        );
    }

    private static Map<Integer, String> readLangTags(ByteBuffer buf, byte[] table, int offset, int storageOffset) {
        if (offset + 2 > table.length) {
            return Map.of();
        }
        int langTagCount = buf.getShort(offset) & 0xFFFF;
        if ((long) offset + 2 + (long) langTagCount * 4 > table.length) {
            return Map.of();
        }
        Map<Integer, String> tags = new HashMap<>();
        for (int i = 0; i < langTagCount; i++) {
            int entry = offset + 2 + i * 4;
            int length = buf.getShort(entry) & 0xFFFF;
            int tagOffset = buf.getShort(entry + 2) & 0xFFFF;
            long start = (long) storageOffset + tagOffset;
            if (start + length <= table.length) {
                tags.put(0x8000 + i, new String(table, (int) start, length, StandardCharsets.UTF_16BE).trim());
            }
        }
        return tags;
    }

    String identifyLicense(String location, Map<String, String> overrides) {
        if (overrides != null) {
            String explicit = overrides.get(location);
            if (explicit == null || explicit.isBlank()) {
                explicit = overrides.get(family);
            }
            if (explicit != null && !explicit.isBlank()) {
                String normalized = SpdxExpressions.normalize(explicit);
                check(normalized != null, "Font license override '" + explicit + "' for " + location
                        + " is not a valid SPDX license expression");
                return normalized;
            }
        }

        if (!licenseDescription.isEmpty() && !licenseDescription.contains("\n") && licenseDescription.length() <= 128) {
            String direct = SpdxExpressions.normalize(licenseDescription);
            if (direct != null) {
                return direct;
            }
        }

        String words = WHITESPACE.matcher(licenseDescription).replaceAll(" ").toLowerCase(Locale.ROOT);
        String url = licenseUrl.toLowerCase(Locale.ROOT);

        if (words.contains("sil open font license") && words.contains("1.1")) {
            return "OFL-1.1";
        }
        if (words.contains("sil open font license") && words.contains("1.0")) {
            return "OFL-1.0";
        }
        if (words.isEmpty() && (url.contains("openfontlicense.org") || url.contains("scripts.sil.org/ofl"))) {
            return "OFL-1.1";
        }
        if (words.contains("bitstream vera fonts copyright")
                || (words.contains("bitstream vera") && url.contains("dejavu"))) {
            return "Bitstream-Vera";
        }
        if ((words.contains("apache license") && words.contains("2.0"))
                || (words.isEmpty() && url.contains("apache.org/licenses/license-2.0"))) {
            return "Apache-2.0";
        }
        if (MIT_LICENSE_PHRASE.matcher(words).find()) {
            return "MIT";
        }
        if (words.contains("ubuntu font licence") && words.contains("1.0")) {
            return "Ubuntu-font-1.0";
        }

        String summary = !licenseDescription.isEmpty() ? "'" + truncate(words, 120) + "'"
                : (!licenseUrl.isEmpty() ? licenseUrl : "absent");
        throw new SbomException("Cannot determine an SPDX license for font " + location + " (" + family
                + "): embedded license metadata is " + summary
                + ". Specify its SPDX license in the licenses parameter of the fonts goal");
    }

    static String normalizeVersion(String raw) {
        if (raw == null || raw.isBlank()) {
            return "";
        }
        String collapsed = WHITESPACE.matcher(raw.split(";", 2)[0]).replaceAll(" ").trim();
        String stripped = VERSION_PREFIX.matcher(collapsed).replaceFirst("").trim();
        return stripped.isEmpty() ? collapsed : stripped;
    }

    private static String normalizeMultiline(String raw) {
        if (raw == null || raw.isBlank()) {
            return "";
        }
        return raw.lines().map(String::stripTrailing).collect(Collectors.joining("\n")).strip();
    }

    private static ByteBuffer readFully(SeekableByteChannel channel, long position, int length) throws IOException {
        channel.position(position);
        ByteBuffer buf = ByteBuffer.allocate(length).order(ByteOrder.BIG_ENDIAN);
        while (buf.hasRemaining()) {
            int read = channel.read(buf);
            if (read < 0) {
                throw new IOException("Unexpected end of font file");
            }
        }
        buf.flip();
        return buf;
    }

    private static Charset charsetFor(int platformId, int encodingId) {
        return switch (platformId) {
            case 0 -> StandardCharsets.UTF_16BE;
            case 3 -> (encodingId == 0 || encodingId == 1 || encodingId == 10) ? StandardCharsets.UTF_16BE : null;
            case 1 -> encodingId == 0 ? MAC_ROMAN : null;
            default -> null;
        };
    }

    private static int priorityOf(int platformId, int encodingId, int languageId, String langTag) {
        if (langTag != null) {
            String tag = langTag.toLowerCase(Locale.ROOT);
            if (tag.equals("en-us") || tag.equals("en")) {
                return 0;
            }
            if (tag.startsWith("en-")) {
                return 1;
            }
        }
        if (platformId == 3 && languageId == 0x0409) {
            return 0;
        }
        if (platformId == 3 && (languageId & 0x03FF) == 0x0009) {
            return 1;
        }
        if (platformId == 0) {
            return 2;
        }
        if (platformId == 1 && encodingId == 0 && languageId == 0) {
            return 3;
        }
        return platformId == 3 ? 4 : 5;
    }

    private static Charset macRomanCharset() {
        try {
            return Charset.forName("x-MacRoman");
        } catch (UnsupportedCharsetException e) {
            return StandardCharsets.ISO_8859_1;
        }
    }

    private static String get(Map<Integer, PrioritizedString> values, int nameId) {
        PrioritizedString found = values.get(nameId);
        return found == null ? "" : found.value;
    }

    private static String truncate(String text, int max) {
        return text.length() <= max ? text : text.substring(0, max) + "...";
    }

    private record PrioritizedString(int priority, String value) {}
}
