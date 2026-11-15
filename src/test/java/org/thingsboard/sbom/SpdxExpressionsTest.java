// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
package org.thingsboard.sbom;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SpdxExpressionsTest {
    @Test
    void identifiersJoinedWithOperatorsAreAnExpression() {
        assertThat(normalize("EPL-2.0 OR BSD-3-Clause")).isEqualTo("EPL-2.0 OR BSD-3-Clause");
        assertThat(normalize("  epl-2.0 or  bsd-3-clause and mit ")).isEqualTo("EPL-2.0 OR BSD-3-Clause AND MIT");
        assertThat(normalize("GPL-2.0-only WITH Classpath-exception-2.0")).isEqualTo("GPL-2.0-only WITH Classpath-exception-2.0");
        assertThat(normalize("(MIT OR EPL-2.0+) AND (GPL-2.0-only with classpath-exception-2.0)"))
                .isEqualTo("(MIT OR EPL-2.0+) AND (GPL-2.0-only WITH Classpath-exception-2.0)");
    }

    @Test
    void oneIdentifierIsNotAnExpression() {
        assertThat(normalize("MIT")).isNull();
        assertThat(normalize("(MIT)")).isNull();
        assertThat(normalize("NONE")).isNull();
        assertThat(normalize("NOASSERTION")).isNull();
    }

    @Test
    void textThatIsNotMadeOfIdentifiersAndOperatorsIsNotAnExpression() {
        assertThat(normalize(null)).isNull();
        assertThat(normalize("")).isNull();
        assertThat(normalize("MIT OR Unknown-1.0")).isNull();
        assertThat(normalize("MIT License OR EPL-2.0")).isNull();
        assertThat(normalize("MIT OR")).isNull();
        assertThat(normalize("OR MIT")).isNull();
        assertThat(normalize("MIT EPL-2.0")).isNull();
        assertThat(normalize("(MIT OR EPL-2.0")).isNull();
        assertThat(normalize("MIT OR EPL-2.0)")).isNull();
        assertThat(normalize("MIT WITH")).isNull();
        assertThat(normalize("MIT WITH EPL-2.0")).isNull();
        assertThat(normalize("Classpath-exception-2.0 OR MIT")).isNull();
        assertThat(normalize("MIT, EPL-2.0")).isNull();
        assertThat(normalize("MIT / EPL-2.0")).isNull();
    }

    private static String normalize(String text) {
        return SpdxExpressions.normalize(text);
    }
}
