// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
package org.thingsboard.sbom;

import org.apache.maven.model.License;
import org.cyclonedx.model.LicenseChoice;
import org.cyclonedx.model.LicenseItem;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class MavenComponentsTest {

    @Test
    void aLicenseNameThatSpdxKnowsBecomesItsId() {
        LicenseChoice licenses = MavenComponents.licenses(List.of(license("Apache-2.0", "https://example.com/license")));

        assertThat(licenses.getItems()).extracting(item -> item.getLicense().getId()).containsExactly("Apache-2.0");
    }

    @Test
    void aLicenseWithAnUnknownNameBecomesTheIdThatItsUrlStandsFor() {
        LicenseChoice licenses = MavenComponents.licenses(List.of(license("The license of this project", "http://www.apache.org/licenses/LICENSE-2.0")));

        assertThat(licenses.getItems()).extracting(item -> item.getLicense().getId()).containsExactly("Apache-2.0");
    }

    @Test
    void theOldAddressOfAnOpenSourceInitiativePageStandsForTheSameLicense() {
        assertThat(ids(license("BSD New license", "http://opensource.org/licenses/BSD-3-Clause"))).containsExactly("BSD-3-Clause");
        assertThat(ids(license("BSD 3", "https://www.opensource.org/licenses/bsd-3-clause.php"))).containsExactly("BSD-3-Clause");
        // The address names a version and nothing later
        assertThat(ids(license("An LGPL license", "https://www.opensource.org/licenses/LGPL-2.1"))).containsExactly("LGPL-2.1-only");
        assertThat(ids(license("A GPL license", "http://www.opensource.org/licenses/gpl-2.0.php"))).containsExactly("GPL-2.0-only");
        assertThat(ids(license("Example License", "https://opensource.org/licenses/unknown"))).containsExactly((String) null);
    }

    @Test
    void aLicenseThatSpdxDoesNotKnowKeepsItsNameAndUrl() {
        LicenseChoice licenses = MavenComponents.licenses(List.of(license(" Example License ", " https://example.com/license ")));

        LicenseItem item = licenses.getItems().get(0);
        assertThat(item.getLicense().getId()).isNull();
        assertThat(item.getLicense().getName()).isEqualTo("Example License");
        assertThat(item.getLicense().getUrl()).isEqualTo("https://example.com/license");
    }

    @Test
    void everyLicenseOfThePomIsListed() {
        LicenseChoice licenses = MavenComponents.licenses(List.of(license("MIT", null), license("Example License", null), license(null, "https://example.com/unknown")));

        assertThat(licenses.getItems()).extracting(item -> item.getLicense().getId() != null ? item.getLicense().getId() : item.getLicense().getName())
                .containsExactly("MIT", "Example License");
    }

    @Test
    void anExpressionAndALicenseAreNotListedTogetherAndTheLaterOneStays() {
        License expression = license("CDDL + GPLv2 with classpath exception", null);

        LicenseChoice licenseLast = MavenComponents.licenses(List.of(expression, license("MIT", null)));
        LicenseChoice expressionLast = MavenComponents.licenses(List.of(license("MIT", null), expression));

        assertThat(licenseLast.getItems()).hasSize(1);
        assertThat(licenseLast.getItems().get(0).getLicense().getId()).isEqualTo("MIT");
        assertThat(expressionLast.getItems()).hasSize(1);
        assertThat(expressionLast.getItems().get(0).getExpression()).isNotNull();
    }

    @Test
    void thePurlHasTheTypeAndTheClassifierOfTheArtifact() {
        assertThat(MavenComponents.purl("org.example", "a", "1.0", "jar", null)).isEqualTo("pkg:maven/org.example/a@1.0?type=jar");
        assertThat(MavenComponents.purl("org.example", "a", "1.0", "jar", "linux-x86_64")).isEqualTo("pkg:maven/org.example/a@1.0?classifier=linux-x86_64&type=jar");
    }

    private static List<String> ids(License license) {
        return MavenComponents.licenses(List.of(license)).getItems().stream().map(item -> item.getLicense().getId()).toList();
    }

    private static License license(String name, String url) {
        License license = new License();
        license.setName(name);
        license.setUrl(url);
        return license;
    }

}
