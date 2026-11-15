// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
package org.thingsboard.sbom;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SpdxExpressionsTest {
    @Test
    void identifiersJoinedWithOperatorsAreAnExpression() {
        assertThat(SpdxExpressions.normalize("EPL-2.0 OR BSD-3-Clause")).isEqualTo("EPL-2.0 OR BSD-3-Clause");
        assertThat(SpdxExpressions.normalize("  epl-2.0 or  bsd-3-clause and mit ")).isEqualTo("EPL-2.0 OR BSD-3-Clause AND MIT");
        assertThat(SpdxExpressions.normalize("GPL-2.0-only WITH Classpath-exception-2.0")).isEqualTo("GPL-2.0-only WITH Classpath-exception-2.0");
        assertThat(SpdxExpressions.normalize("(MIT OR EPL-2.0+) AND (GPL-2.0-only with classpath-exception-2.0)"))
                .isEqualTo("(MIT OR EPL-2.0+) AND (GPL-2.0-only WITH Classpath-exception-2.0)");
    }

    @Test
    void oneIdentifierIsAnExpressionButNotACompoundOne() {
        assertThat(SpdxExpressions.normalize("mit")).isEqualTo("MIT");
        assertThat(SpdxExpressions.normalize("EPL-2.0+")).isEqualTo("EPL-2.0+");
        assertThat(SpdxExpressions.normalizeCompound("MIT")).isNull();
        assertThat(SpdxExpressions.normalizeCompound("MIT OR EPL-2.0")).isEqualTo("MIT OR EPL-2.0");
        assertThat(SpdxExpressions.normalizeCompound("GPL-2.0-only WITH Classpath-exception-2.0")).isEqualTo("GPL-2.0-only WITH Classpath-exception-2.0");
    }

    @Test
    void textThatIsNotMadeOfIdentifiersAndOperatorsIsNotAnExpression() {
        for (String text : new String[] {"", "Apache2", "MIT License", "NONE", "NOASSERTION", "MIT OR Unknown-1.0", "MIT License OR EPL-2.0", "MIT OR", "OR MIT",
                "MIT EPL-2.0", "(MIT OR EPL-2.0", "MIT OR EPL-2.0)", "MIT WITH", "MIT WITH EPL-2.0", "Classpath-exception-2.0 OR MIT", "MIT, EPL-2.0", "MIT / EPL-2.0"}) {
            assertThat(SpdxExpressions.normalize(text)).as(text).isNull();
            assertThat(SpdxExpressions.normalizeCompound(text)).as(text).isNull();
        }
        assertThat(SpdxExpressions.normalize(null)).isNull();
    }
}
