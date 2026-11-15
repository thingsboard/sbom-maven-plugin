// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
package org.thingsboard.sbom;

import org.apache.maven.model.Build;
import org.apache.maven.model.Dependency;
import org.apache.maven.model.License;
import org.apache.maven.model.Model;
import org.apache.maven.model.Plugin;
import org.apache.maven.project.MavenProject;
import org.codehaus.plexus.util.xml.Xpp3Dom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.LicenseChoice;
import org.cyclonedx.model.LicenseItem;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
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
    void aPageOfTheOpenSourceInitiativeStandsForTheVersionItNamesAndNoLaterOne() {
        assertThat(ids(license("A GPL license", "https://opensource.org/license/gpl-2.0"))).containsExactly("GPL-2.0-only");
        assertThat(ids(license("An LGPL license", "https://opensource.org/license/lgpl-2.1"))).containsExactly("LGPL-2.1-only");
        assertThat(ids(license("An AGPL license", "https://opensource.org/license/agpl-3.0"))).containsExactly("AGPL-3.0-only");
        assertThat(ids(license("An MIT license", "https://opensource.org/license/mit"))).containsExactly("MIT");
    }

    @Test
    void aPomNamesWhatMavenFollowsWithTheClassifierOfItsType() {
        Dependency optional = dependency("optional", null, null, null);
        optional.setOptional(true);

        MavenComponents.Pom pom = MavenComponents.pom("org.example:a::jar", List.of(
                dependency("b", null, null, null), dependency("c", "runtime", "native", "jar"), dependency("d", null, null, "test-jar"),
                dependency("tested", "test", null, null), dependency("provided", "provided", null, null), optional), type -> "test-jar".equals(type) ? "tests" : null);

        assertThat(pom.coordinates()).isEqualTo("org.example:a::jar");
        assertThat(pom.dependsOn()).containsExactlyInAnyOrder("org.example:b::jar", "org.example:c:native:jar", "org.example:d:tests:test-jar");
    }

    @Test
    void aLibraryIsOfTheTypeItsPomStatesForCycloneDx() {
        List<String> warnings = new ArrayList<>();

        assertThat(MavenComponents.libraryType(project(null), "pkg:a", warnings::add)).isEqualTo(Component.Type.LIBRARY);
        assertThat(MavenComponents.libraryType(project(new Xpp3Dom("configuration")), "pkg:a", warnings::add)).isEqualTo(Component.Type.LIBRARY);
        assertThat(MavenComponents.libraryType(project(projectType("Framework")), "pkg:a", warnings::add)).isEqualTo(Component.Type.FRAMEWORK);
        assertThat(warnings).isEmpty();
    }

    @Test
    void aLibraryWhosePomStatesNoCycloneDxTypeIsALibrary() {
        List<String> warnings = new ArrayList<>();

        assertThat(MavenComponents.libraryType(project(projectType("${type}")), "pkg:a", warnings::add)).isEqualTo(Component.Type.LIBRARY);
        assertThat(MavenComponents.libraryType(project(projectType(null)), "pkg:b", warnings::add)).isEqualTo(Component.Type.LIBRARY);
        assertThat(warnings).hasSize(2).first().asString().contains("pkg:a", "${type}");
    }

    @Test
    void aNameThatIsAnSpdxExpressionBecomesTheExpression() {
        assertThat(expression(license("EPL-2.0 OR BSD-3-Clause", null))).isEqualTo("EPL-2.0 OR BSD-3-Clause");
        assertThat(expression(license("epl-2.0 or bsd-3-clause", "https://example.org/license"))).isEqualTo("EPL-2.0 OR BSD-3-Clause");
        assertThat(expression(license("GPL-2.0-only WITH Classpath-exception-2.0", null))).isEqualTo("GPL-2.0-only WITH Classpath-exception-2.0");
        assertThat(expression(license("(MIT OR Apache-2.0) AND BSD-3-Clause", null))).isEqualTo("(MIT OR Apache-2.0) AND BSD-3-Clause");
        assertThat(expression(license("(epl-2.0 or BSD-3-Clause)", null))).isEqualTo("(EPL-2.0 OR BSD-3-Clause)");
    }

    @Test
    void aNameWithAnOperatorThatIsNotMadeOfSpdxIdentifiersIsNotAnExpression() {
        for (String name : List.of("MIT OR Example-1.0", "MIT WITH MIT", "Apache OR MIT")) {
            assertThat(MavenComponents.licenses(List.of(license(name, null))).getItems().get(0).getLicense().getName()).isEqualTo(name);
        }
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
    void aNameThatIsAnSpdxExpressionStaysANameNextToAnotherLicense() {
        License expression = license("GPL-2.0-only WITH Classpath-exception-2.0", null);

        for (List<License> licenses : List.of(List.of(license("EPL-2.0", null), expression), List.of(expression, license("EPL-2.0", null)))) {
            assertThat(MavenComponents.licenses(licenses).getItems()).extracting(item -> item.getLicense().getId() != null ? item.getLicense().getId() : item.getLicense().getName())
                    .containsExactlyInAnyOrder("EPL-2.0", "GPL-2.0-only WITH Classpath-exception-2.0");
        }
    }

    @Test
    void thePurlHasTheTypeAndTheClassifierOfTheArtifact() {
        assertThat(MavenComponents.purl("org.example", "a", "1.0", "jar", null)).isEqualTo("pkg:maven/org.example/a@1.0?type=jar");
        assertThat(MavenComponents.purl("org.example", "a", "1.0", "jar", "linux-x86_64")).isEqualTo("pkg:maven/org.example/a@1.0?classifier=linux-x86_64&type=jar");
    }

    private static String expression(License license) {
        return MavenComponents.licenses(List.of(license)).getItems().get(0).getExpression().getValue();
    }

    private static List<String> ids(License license) {
        return MavenComponents.licenses(List.of(license)).getItems().stream().map(item -> item.getLicense().getId()).toList();
    }

    private static Dependency dependency(String name, String scope, String classifier, String type) {
        Dependency dependency = new Dependency();
        dependency.setGroupId("org.example");
        dependency.setArtifactId(name);
        dependency.setScope(scope);
        dependency.setClassifier(classifier);
        if (type != null) {
            dependency.setType(type);
        }
        return dependency;
    }

    private static Xpp3Dom projectType(String value) {
        Xpp3Dom type = new Xpp3Dom("projectType");
        type.setValue(value);
        Xpp3Dom configuration = new Xpp3Dom("configuration");
        configuration.addChild(type);
        return configuration;
    }

    /**
     * A project with the CycloneDX plugin when it has a configuration, else without.
     */
    private static MavenProject project(Xpp3Dom configuration) {
        Model model = new Model();
        model.setBuild(new Build());
        if (configuration != null) {
            Plugin plugin = new Plugin();
            plugin.setGroupId("org.cyclonedx");
            plugin.setArtifactId("cyclonedx-maven-plugin");
            plugin.setConfiguration(configuration);
            model.getBuild().addPlugin(plugin);
        }
        return new MavenProject(model);
    }

    private static License license(String name, String url) {
        License license = new License();
        license.setName(name);
        license.setUrl(url);
        return license;
    }

}
