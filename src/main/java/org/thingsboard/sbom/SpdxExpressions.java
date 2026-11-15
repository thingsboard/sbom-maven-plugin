// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
package org.thingsboard.sbom;

import org.spdx.library.LicenseInfoFactory;
import org.spdx.library.ListedLicenses;
import org.spdx.library.SpdxModelFactory;
import org.spdx.library.model.v3_0_1.expandedlicensing.ConjunctiveLicenseSet;
import org.spdx.library.model.v3_0_1.expandedlicensing.DisjunctiveLicenseSet;
import org.spdx.library.model.v3_0_1.expandedlicensing.OrLaterOperator;
import org.spdx.library.model.v3_0_1.expandedlicensing.WithAdditionOperator;

import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Recognizes an SPDX license expression: license identifiers joined with {@code AND}, {@code OR} and {@code WITH},
 * as in {@code EPL-2.0 OR BSD-3-Clause}. A pom can give one as the name of its license. The SPDX Java library decides
 * what is an expression.
 */
final class SpdxExpressions {
    private static final Pattern TOKEN = Pattern.compile("[()]|[^\\s()]+");
    private static final Map<String, Optional<String>> NORMALIZED = new ConcurrentHashMap<>();

    static {
        // The license list that the library brings, not the one it would download
        if (System.getProperty("org.spdx.useJARLicenseInfoOnly") == null) {
            System.setProperty("org.spdx.useJARLicenseInfoOnly", "true");
        }
        SpdxModelFactory.init();
    }

    private SpdxExpressions() {}

    /**
     * @return the expression with its operators in capitals and its identifiers as SPDX spells them, or null when
     *         the text is not an expression of more than one identifier
     */
    static String normalize(String text) {
        return text == null ? null : NORMALIZED.computeIfAbsent(text.trim(), expression -> Optional.ofNullable(parse(expression))).orElse(null);
    }

    // The library keeps what it parses in one store, so one expression is parsed at a time
    private static synchronized String parse(String text) {
        Object parsed;
        try {
            parsed = LicenseInfoFactory.parseSPDXLicenseString(text);
        } catch (Exception e) {
            return null;
        }
        // One license, and a text that is no expression, are other types
        if (!(parsed instanceof ConjunctiveLicenseSet || parsed instanceof DisjunctiveLicenseSet || parsed instanceof WithAdditionOperator
                || parsed instanceof OrLaterOperator)) {
            return null;
        }
        // The library writes the licenses of a parsed expression in an order of its own: the text keeps its order
        StringBuilder normalized = new StringBuilder();
        Matcher token = TOKEN.matcher(text);
        while (token.find()) {
            String part = token.group();
            if (normalized.length() > 0 && !part.equals(")") && normalized.charAt(normalized.length() - 1) != '(') {
                normalized.append(' ');
            }
            normalized.append(spelled(part));
        }
        return normalized.toString();
    }

    private static String spelled(String token) {
        String operator = token.toUpperCase(Locale.ROOT);
        if (operator.equals("AND") || operator.equals("OR") || operator.equals("WITH") || token.equals("(") || token.equals(")")) {
            return operator;
        }
        boolean orLater = token.endsWith("+");
        String identifier = orLater ? token.substring(0, token.length() - 1) : token;
        ListedLicenses listed = ListedLicenses.getListedLicenses();
        return listed.listedLicenseIdCaseSensitive(identifier).or(() -> listed.listedExceptionIdCaseSensitive(identifier)).orElse(identifier) + (orLater ? "+" : "");
    }
}
