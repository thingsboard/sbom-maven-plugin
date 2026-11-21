// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
package org.thingsboard.sbom;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.thingsboard.sbom.SbomChecks.check;

/**
 * An explicit SPDX license override for a font whose OpenType {@code name} table does not state a recognizable
 * license. {@code font} matches either the font's relative path inside the resources directory (for example
 * {@code fonts/MaterialIcons-Regular.ttf}) or its font family name (for example {@code Material Icons}).
 */
public class FontLicense {
    private String font;
    private String license;

    public FontLicense() {}

    FontLicense(String font, String license) {
        this.font = font;
        this.license = license;
    }

    /**
     * Relative font path (with forward slashes) or font family name.
     */
    public String getFont() {
        return font;
    }

    /**
     * SPDX license expression for the font (for example {@code Apache-2.0} or {@code OFL-1.1}).
     */
    public String getLicense() {
        return license;
    }

    static Map<String, String> toMap(List<FontLicense> entries) {
        Map<String, String> overrides = new LinkedHashMap<>();
        if (entries == null) {
            return overrides;
        }
        for (FontLicense entry : entries) {
            check(entry != null && entry.font != null && !entry.font.isBlank(),
                    "A font license override must specify a non-blank font path or family name");
            check(entry.license != null && !entry.license.isBlank(),
                    "Font license override for '" + entry.font + "' must specify a non-blank SPDX license");
            String key = entry.font.trim().replace('\\', '/');
            String normalized = SpdxExpressions.normalize(entry.license);
            check(normalized != null, "Font license override '" + entry.license + "' for '" + key
                    + "' is not a valid SPDX license expression");
            String previous = overrides.put(key, normalized);
            check(previous == null || previous.equals(normalized),
                    "Duplicate conflicting font license override for '" + key + "'");
        }
        return overrides;
    }
}
