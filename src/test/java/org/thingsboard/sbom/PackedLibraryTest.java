// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
package org.thingsboard.sbom;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class PackedLibraryTest {

    private static final PackedLibrary TOOLS = new PackedLibrary("org.springframework.boot", "spring-boot-jarmode-tools");

    @Test
    void theVersionIsWhatFollowsTheNameInTheFileName() {
        assertThat(TOOLS.versionIn("spring-boot-jarmode-tools-3.5.15.jar", () -> null)).isEqualTo("3.5.15");
    }

    @Test
    void aVersionThatStartsWithNoDigitIsTakenWhenTheLibraryStatesIt() {
        assertThat(TOOLS.versionIn("spring-boot-jarmode-tools-RELEASE.jar", () -> "RELEASE")).isEqualTo("RELEASE");
        assertThat(TOOLS.versionIn("spring-boot-jarmode-tools-extra-1.0.jar", () -> "1.0")).isNull();
    }

    @Test
    void theFileOfAnotherLibraryGivesNoVersionAndIsNotAskedForOne() {
        assertThat(TOOLS.versionIn("spring-boot-3.5.15.jar", () -> {
            throw new AssertionError("not asked");
        })).isNull();
        assertThat(TOOLS.versionIn("spring-boot-jarmode-tools-.jar", () -> "")).isNull();
    }

}
