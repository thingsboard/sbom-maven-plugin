// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
package org.thingsboard.sbom;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.cyclonedx.Version;
import org.cyclonedx.parsers.JsonParser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SbomBundledTest {

    static final String WINSW_REF = "pkg:maven/com.sun.winsw/winsw@2.0.1?classifier=bin&type=exe";

    @TempDir
    Path tempDir;

    Path bundle;
    Path service;

    @BeforeEach
    void createFiles() throws IOException {
        bundle = Files.writeString(tempDir.resolve("extension.js"), "console.log('extension');");
        service = Files.writeString(tempDir.resolve("service.exe"), "service");
    }

    List<PackageFile> packages() {
        return List.of(new PackageFile("deb", null, null, false), new PackageFile("zip", null, null, false));
    }

    List<BundledComponent> components() {
        return List.of(
                new BundledComponent("library", "gateway-management-extension", "4.4.0.1", bundle.toFile()).license("Apache-2.0"),
                new BundledComponent("application", "winsw", "2.0.1", service.toFile())
                        .group("com.sun.winsw").purl(WINSW_REF).license("MIT").packages(List.of("zip")));
    }

    @Test
    void theRootIsWhatThePackageBundles() {
        JsonNode root = SbomBundled.describe("thingsboard", "4.4.0.1", "deb", components()).path("metadata").path("component");

        assertThat(root.path("bom-ref").asText()).isEqualTo("thingsboard-deb-bundled@4.4.0.1");
        assertThat(root.path("name").asText()).isEqualTo("thingsboard-deb-bundled");
        assertThat(root.path("version").asText()).isEqualTo("4.4.0.1");
    }

    @Test
    void listsTheComponentsOfThePackageOnly() {
        assertThat(SbomChecks.componentRefs(SbomBundled.describe("thingsboard", "4.4.0.1", "deb", components()))).containsExactly("gateway-management-extension@4.4.0.1");
        assertThat(SbomChecks.componentRefs(SbomBundled.describe("thingsboard", "4.4.0.1", "zip", components()))).containsExactly("gateway-management-extension@4.4.0.1", WINSW_REF);
    }

    @Test
    void theRootDependsOnEveryComponent() throws IOException {
        ObjectNode bom = SbomBundled.describe("thingsboard", "4.4.0.1", "zip", components());

        assertThat(Boms.graph(bom).get("thingsboard-zip-bundled@4.4.0.1")).containsExactlyInAnyOrder("gateway-management-extension@4.4.0.1", WINSW_REF);
        assertThat(new JsonParser().validate(bom, Version.VERSION_16)).isEmpty();
    }

    @Test
    void aPackageThatBundlesNothingGetsAnSbomWithoutComponents() throws IOException {
        ObjectNode bom = SbomBundled.describe("thingsboard", "4.4.0.1", "deb", List.of());

        assertThat(bom.path("components")).isEmpty();
        assertThat(Boms.graph(bom).get("thingsboard-deb-bundled@4.4.0.1")).isEmpty();
        assertThat(new JsonParser().validate(bom, Version.VERSION_16)).isEmpty();
    }

    @Test
    void aComponentKeepsItsExternalReferences() throws IOException {
        List<BundledComponent> components = List.of(new BundledComponent("application", "node", "22.23.4", null).license("MIT")
                .externalReferences(List.of(new ExternalReference("license", "https://raw.githubusercontent.com/nodejs/node/v22.23.4/LICENSE"))));

        ObjectNode bom = SbomBundled.describe("thingsboard", "4.4.0.1", "deb", components);

        assertThat(bom.path("components").get(0).path("externalReferences")).isEqualTo(Boms.MAPPER.readTree(
                "[{\"url\": \"https://raw.githubusercontent.com/nodejs/node/v22.23.4/LICENSE\", \"type\": \"license\"}]"));
        assertThat(new JsonParser().validate(bom, Version.VERSION_16)).isEmpty();
    }

    @Test
    void anExternalReferenceNeedsATypeAndAUrl() {
        List<BundledComponent> components = List.of(new BundledComponent("application", "node", "22.23.4", null)
                .externalReferences(List.of(new ExternalReference("license", " "))));

        assertThatThrownBy(() -> SbomBundled.describe("thingsboard", "4.4.0.1", "deb", components))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("Bundled component node@22.23.4 has an external reference without a type or a url");
    }

    @Test
    void anExternalReferenceOfAnUnknownTypeFails() {
        List<BundledComponent> components = List.of(new BundledComponent("application", "node", "22.23.4", null)
                .externalReferences(List.of(new ExternalReference("licence", "https://nodejs.org"))));

        assertThatThrownBy(() -> SbomBundled.describe("thingsboard", "4.4.0.1", "deb", components))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("/components/0/externalReferences/0/type: does not have a value in the enumeration");
    }

    @Test
    void theSerialNumberIsTheSameForTheSameContents() {
        assertThat(SbomBundled.describe("thingsboard", "4.4.0.1", "deb", components()).path("serialNumber"))
                .isEqualTo(SbomBundled.describe("thingsboard", "4.4.0.1", "deb", components()).path("serialNumber"))
                .isNotEqualTo(SbomBundled.describe("thingsboard", "4.4.0.1", "zip", components()).path("serialNumber"));
    }

    @Test
    void writesOneSbomPerPackageThatIsNotSkipped() throws IOException {
        List<PackageFile> packages = List.of(new PackageFile("deb", null, null, false), new PackageFile("rpm", null, null, true),
                new PackageFile("zip", null, null, false));

        List<Path> outputs = SbomBundled.writeAll(tempDir.resolve("sbom"), "thingsboard", "4.4.0.1", packages, components());

        assertThat(outputs).containsExactly(tempDir.resolve("sbom/thingsboard-deb.bundled.cdx.json"), tempDir.resolve("sbom/thingsboard-zip.bundled.cdx.json"));
        assertThat(Boms.MAPPER.readTree(outputs.get(1).toFile())).isEqualTo(SbomBundled.describe("thingsboard", "4.4.0.1", "zip", components()));
    }

    @Test
    void writesNothingWhenAComponentFails() throws IOException {
        Files.delete(service);

        assertThatThrownBy(() -> SbomBundled.writeAll(tempDir.resolve("sbom"), "thingsboard", "4.4.0.1", packages(), components()))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("service.exe, which does not exist");

        assertThat(tempDir.resolve("sbom/thingsboard-deb.bundled.cdx.json")).doesNotExist();
    }

    @Test
    void configCheckNeedsOnlyThePackageIds() {
        SbomBundled.checkConfig(packages(), components());
    }

    @Test
    void configCheckRejectsAnUnknownPackage() {
        assertThatThrownBy(() -> SbomBundled.checkConfig(List.of(new PackageFile("deb", null, null, false)), components()))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("refers to unknown package zip; known packages are [deb]");
    }

    @Test
    void configCheckRejectsAPackageWithoutId() {
        assertThatThrownBy(() -> SbomBundled.checkConfig(List.of(new PackageFile(" ", null, null, false)), List.of()))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("A package has no id");
    }

}
