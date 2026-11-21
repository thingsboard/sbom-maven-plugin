// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
package org.thingsboard.sbom;

import org.apache.fontbox.ttf.NameRecord;
import org.apache.fontbox.ttf.NamingTable;
import org.apache.fontbox.ttf.OTFParser;
import org.apache.fontbox.ttf.TrueTypeFont;
import org.apache.pdfbox.io.RandomAccessRead;
import org.apache.pdfbox.io.RandomAccessReadBuffer;
import org.apache.pdfbox.io.RandomAccessReadBufferedFile;
import org.cyclonedx.model.LicenseChoice;
import org.cyclonedx.model.LicenseItem;
import org.cyclonedx.util.LicenseResolver;

import java.io.IOException;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static org.thingsboard.sbom.SbomChecks.check;

/**
 * Reads licensing and version metadata from the OpenType/TrueType {@code name} table of a {@code .ttf} or {@code .otf}
 * font file using Apache FontBox.
 */
record FontMetadata(String family, String version, String copyright, String licenseDescription, String licenseUrl) {

    private static final int NAME_LICENSE = 13;
    private static final int NAME_LICENSE_URL = 14;
    private static final int NAME_TYPOGRAPHIC_FAMILY = 16;

    private static final Pattern VERSION_PREFIX = Pattern.compile("^(?:version\\s+)+", Pattern.CASE_INSENSITIVE);
    private static final Pattern WHITESPACE = Pattern.compile("\\s+");
    private static final Pattern MIT_LICENSE_PHRASE = Pattern.compile("\\bthe mit license\\b|\\bmit license\\b");

    static FontMetadata read(Path file) {
        try (RandomAccessRead input = new RandomAccessReadBufferedFile(file)) {
            return parse(input, file.toString());
        } catch (IOException e) {
            throw new SbomException("Failed to read font " + file, e);
        }
    }

    static FontMetadata parse(byte[] data, String source) {
        try (RandomAccessRead input = new RandomAccessReadBuffer(data)) {
            return parse(input, source);
        } catch (IOException e) {
            throw new SbomException("Failed to read font " + source, e);
        }
    }

    private static FontMetadata parse(RandomAccessRead input, String source) throws IOException {
        try (TrueTypeFont font = new OTFParser(true).parse(input)) {
            NamingTable naming = font.getNaming();
            check(naming != null, "Font " + source + " has no OpenType name table");

            Map<Integer, PrioritizedString> values = new HashMap<>();
            for (NameRecord record : naming.getNameRecords()) {
                int nameId = record.getNameId();
                if (nameId != NameRecord.NAME_COPYRIGHT && nameId != NameRecord.NAME_FONT_FAMILY_NAME
                        && nameId != NameRecord.NAME_VERSION && nameId != NAME_LICENSE
                        && nameId != NAME_LICENSE_URL && nameId != NAME_TYPOGRAPHIC_FAMILY) {
                    continue;
                }
                String text = record.getString();
                if (text == null || text.isBlank()) {
                    continue;
                }
                int priority = priorityOf(record.getPlatformId(), record.getPlatformEncodingId(), record.getLanguageId());
                values.merge(nameId, new PrioritizedString(priority, text.trim()),
                        (existing, incoming) -> incoming.priority < existing.priority ? incoming : existing);
            }

            String typographic = get(values, NAME_TYPOGRAPHIC_FAMILY);
            String family = !typographic.isEmpty() ? typographic : get(values, NameRecord.NAME_FONT_FAMILY_NAME);
            check(!family.isEmpty(), "Font " + source + " has no family name in its OpenType name table");

            return new FontMetadata(
                    family,
                    normalizeVersion(get(values, NameRecord.NAME_VERSION)),
                    normalizeMultiline(get(values, NameRecord.NAME_COPYRIGHT)),
                    normalizeMultiline(get(values, NAME_LICENSE)),
                    get(values, NAME_LICENSE_URL)
            );
        }
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
            if (resolvedUrl != null) {
                return resolvedUrl;
            }
            if (url.contains("openfontlicense.org") || url.contains("scripts.sil.org/ofl")) {
                return "OFL-1.1";
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
            return platformId == NameRecord.PLATFORM_WINDOWS ? 4 : 5;
        }
        if (platformId == NameRecord.PLATFORM_WINDOWS && languageId == NameRecord.LANGUAGE_WINDOWS_EN_US) {
            return 0;
        }
        if (platformId == NameRecord.PLATFORM_WINDOWS && (languageId & 0x03FF) == 0x0009) {
            return 1;
        }
        if (platformId == NameRecord.PLATFORM_UNICODE) {
            return 2;
        }
        if (platformId == NameRecord.PLATFORM_MACINTOSH
                && encodingId == NameRecord.ENCODING_MACINTOSH_ROMAN
                && languageId == NameRecord.LANGUAGE_MACINTOSH_ENGLISH) {
            return 3;
        }
        return platformId == NameRecord.PLATFORM_WINDOWS ? 4 : 5;
    }

    static String normalizeVersion(String raw) {
        if (raw == null || raw.isBlank()) {
            return "";
        }
        String collapsed = WHITESPACE.matcher(raw.split(";", 2)[0]).replaceAll(" ").trim();
        String stripped = VERSION_PREFIX.matcher(collapsed).replaceFirst("").trim();
        return stripped.isEmpty() ? collapsed : stripped;
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
