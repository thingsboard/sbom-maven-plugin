// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
package org.thingsboard.sbom;

import org.apache.commons.compress.utils.SeekableInMemoryByteChannel;
import org.cyclonedx.model.LicenseChoice;
import org.cyclonedx.model.LicenseItem;
import org.cyclonedx.util.LicenseResolver;

import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
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
 * font file without loading outline or glyph tables.
 */
record FontMetadata(String family, String version, String copyright, String licenseDescription, String licenseUrl) {

    private static final int SFNT_TRUETYPE = 0x00010000;
    private static final int SFNT_OTTO = 0x4F54544F; // 'OTTO'
    private static final int SFNT_TRUE = 0x74727565; // 'true'
    private static final int TAG_NAME = 0x6E616D65;  // 'name'
    private static final long MAX_NAME_TABLE_BYTES = 16L * 1024 * 1024;

    static final int PLATFORM_UNICODE = 0;
    static final int PLATFORM_MACINTOSH = 1;
    static final int PLATFORM_WINDOWS = 3;
    static final int ENCODING_MAC_ROMAN = 0;
    static final int ENCODING_WINDOWS_SYMBOL = 0;
    static final int ENCODING_WINDOWS_UNICODE_BMP = 1;
    static final int ENCODING_WINDOWS_UNICODE_FULL = 10;
    static final int LANGUAGE_MAC_ENGLISH = 0;
    static final int LANGUAGE_WINDOWS_EN_US = 0x0409;

    private static final int NAME_COPYRIGHT = 0;
    private static final int NAME_FONT_FAMILY = 1;
    private static final int NAME_VERSION = 5;
    private static final int NAME_LICENSE = 13;
    private static final int NAME_LICENSE_URL = 14;
    private static final int NAME_TYPOGRAPHIC_FAMILY = 16;

    static final Charset MAC_ROMAN = Charset.isSupported("x-MacRoman")
            ? Charset.forName("x-MacRoman")
            : StandardCharsets.ISO_8859_1;

    private static final Pattern VERSION_PREFIX = Pattern.compile("^(?:version(?:\\s+|$))+", Pattern.CASE_INSENSITIVE);
    private static final Pattern WHITESPACE = Pattern.compile("\\s+");
    private static final Pattern MIT_LICENSE_PHRASE = Pattern.compile("\\bthe mit license\\b|\\bmit license\\b");

    static FontMetadata read(Path file) {
        try (SeekableByteChannel channel = Files.newByteChannel(file, StandardOpenOption.READ)) {
            return parse(channel, file.toString());
        } catch (IOException e) {
            throw new SbomException("Failed to read font " + file, e);
        }
    }

    static FontMetadata parse(byte[] data, String source) {
        try (SeekableByteChannel channel = new SeekableInMemoryByteChannel(data)) {
            return parse(channel, source);
        } catch (IOException e) {
            throw new SbomException("Failed to read font " + source, e);
        }
    }

    private static FontMetadata parse(SeekableByteChannel channel, String source) throws IOException {
        byte[] nameTable = readNameTable(channel, source);
        ByteBuffer buf = ByteBuffer.wrap(nameTable).order(ByteOrder.BIG_ENDIAN);

        int format = buf.getShort(0) & 0xFFFF;
        check(format == 0 || format == 1, "Font " + source + " has unsupported OpenType name table format " + format);
        int count = buf.getShort(2) & 0xFFFF;
        int storageOffset = buf.getShort(4) & 0xFFFF;
        check(6 + count * 12 <= nameTable.length && storageOffset <= nameTable.length,
                "Font " + source + " has an invalid OpenType name table");

        Map<Integer, PrioritizedString> values = new HashMap<>();
        for (int i = 0; i < count; i++) {
            int base = 6 + i * 12;
            int platformId = buf.getShort(base) & 0xFFFF;
            int encodingId = buf.getShort(base + 2) & 0xFFFF;
            int languageId = buf.getShort(base + 4) & 0xFFFF;
            int nameId = buf.getShort(base + 6) & 0xFFFF;
            if (nameId != NAME_COPYRIGHT && nameId != NAME_FONT_FAMILY && nameId != NAME_VERSION
                    && nameId != NAME_LICENSE && nameId != NAME_LICENSE_URL && nameId != NAME_TYPOGRAPHIC_FAMILY) {
                continue;
            }
            int length = buf.getShort(base + 8) & 0xFFFF;
            int offset = buf.getShort(base + 10) & 0xFFFF;
            int start = storageOffset + offset;
            if (length == 0 || start + length > nameTable.length) {
                continue;
            }
            Charset charset = charsetFor(platformId, encodingId);
            if (charset == null) {
                continue;
            }
            String text = new String(nameTable, start, length, charset).trim();
            if (text.isEmpty()) {
                continue;
            }
            int priority = priorityOf(platformId, encodingId, languageId);
            values.merge(nameId, new PrioritizedString(priority, text),
                    (existing, incoming) -> incoming.priority < existing.priority ? incoming : existing);
        }

        String typographic = get(values, NAME_TYPOGRAPHIC_FAMILY);
        String family = !typographic.isEmpty() ? typographic : get(values, NAME_FONT_FAMILY);
        check(!family.isEmpty(), "Font " + source + " has no family name in its OpenType name table");

        return new FontMetadata(
                family,
                normalizeVersion(get(values, NAME_VERSION)),
                normalizeMultiline(get(values, NAME_COPYRIGHT)),
                normalizeMultiline(get(values, NAME_LICENSE)),
                get(values, NAME_LICENSE_URL)
        );
    }

    private static byte[] readNameTable(SeekableByteChannel channel, String source) throws IOException {
        long fileSize = channel.size();
        if (fileSize < 12) {
            throw new IOException("Font file is too short (" + fileSize + " bytes)");
        }
        ByteBuffer header = ByteBuffer.allocate(12).order(ByteOrder.BIG_ENDIAN);
        readFully(channel, header);
        int sfntVersion = header.getInt(0);
        if (sfntVersion != SFNT_TRUETYPE && sfntVersion != SFNT_OTTO && sfntVersion != SFNT_TRUE) {
            throw new IOException(String.format(Locale.ROOT, "Unsupported SFNT header 0x%08X", sfntVersion));
        }
        int numTables = header.getShort(4) & 0xFFFF;
        long dirSize = numTables * 16L;
        if (numTables == 0 || 12L + dirSize > fileSize) {
            throw new IOException("Truncated SFNT table directory (" + numTables + " tables)");
        }
        ByteBuffer directory = ByteBuffer.allocate((int) dirSize).order(ByteOrder.BIG_ENDIAN);
        readFully(channel, directory);
        for (int i = 0; i < numTables; i++) {
            int entry = i * 16;
            if (directory.getInt(entry) != TAG_NAME) {
                continue;
            }
            long offset = Integer.toUnsignedLong(directory.getInt(entry + 8));
            long length = Integer.toUnsignedLong(directory.getInt(entry + 12));
            if (length < 6 || length > MAX_NAME_TABLE_BYTES || offset + length > fileSize) {
                throw new IOException("Invalid OpenType name table bounds (offset=" + offset + ", length=" + length + ")");
            }
            byte[] bytes = new byte[(int) length];
            channel.position(offset);
            readFully(channel, ByteBuffer.wrap(bytes));
            return bytes;
        }
        throw new SbomException("Font " + source + " has no OpenType name table");
    }

    private static void readFully(SeekableByteChannel channel, ByteBuffer target) throws IOException {
        while (target.hasRemaining()) {
            if (channel.read(target) < 0) {
                throw new EOFException("Unexpected end of font stream");
            }
        }
        target.flip();
    }

    private static Charset charsetFor(int platformId, int encodingId) {
        if (platformId == PLATFORM_UNICODE) {
            return StandardCharsets.UTF_16BE;
        }
        if (platformId == PLATFORM_WINDOWS && (encodingId == ENCODING_WINDOWS_SYMBOL
                || encodingId == ENCODING_WINDOWS_UNICODE_BMP || encodingId == ENCODING_WINDOWS_UNICODE_FULL)) {
            return StandardCharsets.UTF_16BE;
        }
        if (platformId == PLATFORM_MACINTOSH && encodingId == ENCODING_MAC_ROMAN) {
            return MAC_ROMAN;
        }
        return null;
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
            String resolved = resolveSpdx(licenseDescription);
            if (resolved != null) {
                return resolved;
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
        if (words.contains("bitstream vera fonts copyright")
                || (words.contains("bitstream vera") && url.contains("dejavu"))) {
            return "Bitstream-Vera";
        }
        if (words.contains("apache license") && words.contains("2.0")) {
            return "Apache-2.0";
        }
        if (MIT_LICENSE_PHRASE.matcher(words).find()) {
            return "MIT";
        }
        if (words.contains("ubuntu font licence") && words.contains("1.0")) {
            return "Ubuntu-font-1.0";
        }

        if (words.isEmpty() && !licenseUrl.isEmpty()) {
            String resolvedUrl = resolveSpdx(licenseUrl);
            if (resolvedUrl == null) {
                String altUrl = licenseUrl.endsWith("/")
                        ? licenseUrl.substring(0, licenseUrl.length() - 1)
                        : licenseUrl + "/";
                resolvedUrl = resolveSpdx(altUrl);
            }
            if (resolvedUrl != null) {
                return resolvedUrl;
            }
            if (url.contains("openfontlicense.org") || url.contains("scripts.sil.org/ofl")) {
                return "OFL-1.1";
            }
            if (url.contains("apache.org/licenses/license-2.0")) {
                return "Apache-2.0";
            }
        }

        String summary = !licenseDescription.isEmpty() ? "'" + truncate(words, 120) + "'"
                : (!licenseUrl.isEmpty() ? licenseUrl : "absent");
        throw new SbomException("Cannot determine an SPDX license for font " + location + " (" + family
                + "): embedded license metadata is " + summary
                + ". Specify its SPDX license in the licenses parameter of the fonts goal");
    }

    static int priorityOf(int platformId, int encodingId, int languageId) {
        // OpenType name table Format 1 uses languageId >= 0x8000 as a language-tag index,
        // never a Windows LCID or language-neutral Format 0 record.
        if (languageId >= 0x8000) {
            return platformId == PLATFORM_WINDOWS ? 4 : 5;
        }
        if (platformId == PLATFORM_WINDOWS && languageId == LANGUAGE_WINDOWS_EN_US) {
            return 0;
        }
        if (platformId == PLATFORM_WINDOWS && (languageId & 0x03FF) == 0x0009) {
            return 1;
        }
        if (platformId == PLATFORM_UNICODE) {
            return 2;
        }
        if (platformId == PLATFORM_MACINTOSH
                && encodingId == ENCODING_MAC_ROMAN
                && languageId == LANGUAGE_MAC_ENGLISH) {
            return 3;
        }
        return platformId == PLATFORM_WINDOWS ? 4 : 5;
    }

    static String normalizeVersion(String raw) {
        if (raw == null || raw.isBlank()) {
            return "";
        }
        String collapsed = WHITESPACE.matcher(raw.split(";", 2)[0]).replaceAll(" ").trim();
        return VERSION_PREFIX.matcher(collapsed).replaceFirst("");
    }

    private static String resolveSpdx(String nameOrUrl) {
        LicenseChoice choice = LicenseResolver.resolve(nameOrUrl, false);
        if (choice == null || choice.getItems() == null) {
            return null;
        }
        for (LicenseItem item : choice.getItems()) {
            if (item.getLicense() != null && item.getLicense().getId() != null) {
                return item.getLicense().getId();
            }
            if (item.getExpression() != null && item.getExpression().getValue() != null) {
                return SpdxExpressions.normalize(item.getExpression().getValue());
            }
        }
        return null;
    }

    private static String normalizeMultiline(String raw) {
        if (raw == null || raw.isBlank()) {
            return "";
        }
        return raw.lines().map(String::stripTrailing).collect(Collectors.joining("\n")).strip();
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
