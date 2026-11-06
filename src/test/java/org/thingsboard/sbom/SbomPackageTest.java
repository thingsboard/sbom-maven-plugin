package org.thingsboard.sbom;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.cyclonedx.Version;
import org.cyclonedx.parsers.JsonParser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SbomPackageTest {

    static final String DEB_PURL = "pkg:deb/thingsboard/thingsboard@4.4.0.1-1?arch=all";
    static final String APP_REF = "pkg:maven/org.thingsboard/application@4.4.1-SNAPSHOT?type=jar";

    @TempDir
    Path tempDir;

    Path deb;
    Path zip;
    Path bundle;
    Path registry;
    Path certificate;

    @BeforeEach
    void createFiles() throws IOException {
        deb = Files.writeString(tempDir.resolve("thingsboard.deb"), "deb contents");
        zip = Files.writeString(tempDir.resolve("thingsboard-windows.zip"), "zip contents");
        bundle = Files.writeString(tempDir.resolve("extension.js"), "console.log('extension');");
        registry = Files.createDirectory(tempDir.resolve("registry"));
        Files.writeString(registry.resolve("3.xml"), "<LWM2M/>");
        try (InputStream in = SbomPackageTest.class.getResourceAsStream("/fixtures/root-ca.crt.pem")) {
            certificate = tempDir.resolve("root-ca.crt.pem");
            Files.copy(in, certificate);
        }
    }

    static ObjectNode application() {
        ObjectNode merged = SbomMerger.merge(Boms.mavenFixture(), Boms.npmFixture(), Boms.HOST_PREFIX);
        return SbomMetadata.apply(merged, SbomMetadataTest.THINGSBOARD, SbomMetadataTest.THINGSBOARD, SbomMetadataTest.THINGSBOARD);
    }

    PackageFile debPackage() {
        return new PackageFile("deb", deb.toFile(), DEB_PURL, false);
    }

    PackageFile zipPackage() {
        return new PackageFile("zip", zip.toFile(), "pkg:generic/thingsboard/thingsboard-windows@4.4.0.1", false);
    }

    List<BundledComponent> bundled() {
        return List.of(
                new BundledComponent("library", "gateway-management-extension", "4.4.0.1", bundle.toFile())
                        .supplier(SbomMetadataTest.THINGSBOARD).license("Apache-2.0").description("Gateway UI extension"),
                new BundledComponent("data", "lwm2m-registry", null, registry.toFile()),
                new BundledComponent("cryptographic-asset", "DigiCert Global Root G2", null, certificate.toFile()),
                new BundledComponent("application", "winsw", "2.0.1", zip.toFile())
                        .group("com.sun.winsw").purl("pkg:maven/com.sun.winsw/winsw@2.0.1?classifier=bin&type=exe").packages(List.of("zip")));
    }

    ObjectNode describeDeb() {
        return SbomPackage.describe(application(), "thingsboard", "4.4.0.1", debPackage(), bundled());
    }

    @Test
    void thePackageIsTheRootComponent() throws IOException {
        JsonNode root = describeDeb().path("metadata").path("component");

        assertThat(root.path("type").asText()).isEqualTo("application");
        assertThat(root.path("bom-ref").asText()).isEqualTo(DEB_PURL);
        assertThat(root.path("purl").asText()).isEqualTo(DEB_PURL);
        assertThat(root.path("name").asText()).isEqualTo("thingsboard");
        assertThat(root.path("version").asText()).isEqualTo("4.4.0.1");
        assertThat(root.path("hashes")).isEqualTo(Boms.MAPPER.readTree("""
                [{"alg":"SHA-256","content":"%s"},{"alg":"SHA-512","content":"%s"}]""".formatted(sha("SHA-256", deb), sha("SHA-512", deb))));
    }

    @Test
    void thePackageTakesLicenseDescriptionManufacturerAndWebsiteFromTheApplication() {
        JsonNode applicationRoot = application().path("metadata").path("component");
        JsonNode root = describeDeb().path("metadata").path("component");

        assertThat(root.path("licenses")).isEqualTo(applicationRoot.path("licenses"));
        assertThat(root.path("description")).isEqualTo(applicationRoot.path("description"));
        assertThat(root.path("manufacturer")).isEqualTo(applicationRoot.path("manufacturer"));
        assertThat(root.path("externalReferences")).hasSize(1);
        assertThat(root.path("externalReferences").get(0).path("type").asText()).isEqualTo("website");
    }

    @Test
    void sbomMetadataIsCarriedOver() {
        JsonNode applicationMetadata = application().path("metadata");
        JsonNode metadata = describeDeb().path("metadata");

        assertThat(metadata.path("manufacturer")).isEqualTo(applicationMetadata.path("manufacturer"));
        assertThat(metadata.path("supplier")).isEqualTo(applicationMetadata.path("supplier"));
        assertThat(metadata.path("tools")).isEqualTo(applicationMetadata.path("tools"));
        assertThat(metadata.path("lifecycles")).isEqualTo(applicationMetadata.path("lifecycles"));
        assertThat(metadata.has("properties")).isFalse();
        assertThat(metadata.has("timestamp")).isFalse();
    }

    @Test
    void theApplicationAndAllItsComponentsAreKeptUnchanged() {
        ObjectNode application = application();
        JsonNode described = describeDeb();

        List<JsonNode> components = new ArrayList<>();
        described.path("components").forEach(components::add);
        assertThat(components).contains(application.path("metadata").path("component"));
        application.path("components").forEach(component -> assertThat(components).contains(component));
        List<JsonNode> dependencies = new ArrayList<>();
        described.path("dependencies").forEach(dependencies::add);
        application.path("dependencies").forEach(dependency -> assertThat(dependencies).contains(dependency));
    }

    @Test
    void thePackageDependsOnTheApplicationAndTheBundledComponents() {
        JsonNode described = describeDeb();

        assertThat(Boms.graph(described).get(DEB_PURL))
                .containsExactlyInAnyOrder(APP_REF, "gateway-management-extension@4.4.0.1", "lwm2m-registry", "DigiCert Global Root G2");
        assertThat(Boms.reachable(described, DEB_PURL)).containsAll(SbomChecks.componentRefs(described));
    }

    @Test
    void npmComponentsMergedIntoTheApplicationStayReachableFromThePackage() {
        JsonNode described = describeDeb();

        Set<String> reachable = Boms.reachable(described, DEB_PURL);
        Boms.npmFixture().path("components").forEach(component -> assertThat(reachable).contains(component.path("bom-ref").asText()));
    }

    @Test
    void aBundledFileGetsHashesLicenseAndSupplier() throws IOException {
        JsonNode extension = component(describeDeb(), "gateway-management-extension@4.4.0.1");

        assertThat(extension.path("type").asText()).isEqualTo("library");
        assertThat(extension.path("version").asText()).isEqualTo("4.4.0.1");
        assertThat(extension.path("description").asText()).isEqualTo("Gateway UI extension");
        assertThat(extension.path("licenses")).isEqualTo(Boms.MAPPER.readTree("[{\"expression\":\"Apache-2.0\"}]"));
        assertThat(extension.path("supplier")).isEqualTo(Boms.MAPPER.readTree("{\"name\":\"ThingsBoard, Inc.\",\"url\":[\"https://thingsboard.io\"]}"));
        assertThat(extension.path("hashes").get(1).path("content").asText()).isEqualTo(sha("SHA-512", bundle));
    }

    @Test
    void aBundledComponentCarriesItsCpe() {
        List<BundledComponent> components = List.of(new BundledComponent("application", "chromium", "139.0.7258.5", bundle.toFile())
                .purl("pkg:generic/chromium@139.0.7258.5?os=linux").cpe("cpe:2.3:a:google:chrome:139.0.7258.5:*:*:*:*:*:*:*"));

        JsonNode described = SbomPackage.describe(application(), "thingsboard", "4.4.0.1", debPackage(), components);

        assertThat(component(described, "pkg:generic/chromium@139.0.7258.5?os=linux").path("cpe").asText())
                .isEqualTo("cpe:2.3:a:google:chrome:139.0.7258.5:*:*:*:*:*:*:*");
    }

    @Test
    void failsOnAnInvalidCpe() {
        List<BundledComponent> components = List.of(new BundledComponent("application", "chromium", "139.0.7258.5", bundle.toFile()).cpe("google chrome"));

        assertThatThrownBy(() -> SbomPackage.describe(application(), "thingsboard", "4.4.0.1", debPackage(), components))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("Bundled component chromium@139.0.7258.5 has an invalid cpe google chrome");
    }

    @Test
    void theSameComponentCanBeDeclaredPerPackageWithDifferentPurls() {
        List<BundledComponent> components = List.of(
                new BundledComponent("application", "chromium", "139.0.7258.5", bundle.toFile()).purl("pkg:generic/chromium@139.0.7258.5?os=linux").packages(List.of("deb")),
                new BundledComponent("application", "chromium", "139.0.7258.5", bundle.toFile()).purl("pkg:generic/chromium@139.0.7258.5?os=windows").packages(List.of("zip")));

        SbomPackage.checkConfig(List.of(debPackage(), zipPackage()), components);
        JsonNode deb = SbomPackage.describe(application(), "thingsboard", "4.4.0.1", debPackage(), components);
        JsonNode windows = SbomPackage.describe(application(), "thingsboard", "4.4.0.1", zipPackage(), components);

        assertThat(SbomChecks.componentRefs(deb)).contains("pkg:generic/chromium@139.0.7258.5?os=linux").doesNotContain("pkg:generic/chromium@139.0.7258.5?os=windows");
        assertThat(SbomChecks.componentRefs(windows)).contains("pkg:generic/chromium@139.0.7258.5?os=windows").doesNotContain("pkg:generic/chromium@139.0.7258.5?os=linux");
    }

    @Test
    void aBundledDirectoryHasNoHashes() {
        JsonNode registryComponent = component(describeDeb(), "lwm2m-registry");

        assertThat(registryComponent.path("type").asText()).isEqualTo("data");
        assertThat(registryComponent.has("hashes")).isFalse();
        assertThat(registryComponent.has("version")).isFalse();
    }

    @Test
    void aCertificateGetsItsPropertiesFromTheFile() {
        JsonNode crypto = component(describeDeb(), "DigiCert Global Root G2").path("cryptoProperties");

        assertThat(crypto.path("assetType").asText()).isEqualTo("certificate");
        JsonNode properties = crypto.path("certificateProperties");
        assertThat(properties.path("subjectName").asText()).isEqualTo("CN=DigiCert Global Root G2,OU=www.digicert.com,O=DigiCert Inc,C=US");
        assertThat(properties.path("issuerName").asText()).isEqualTo(properties.path("subjectName").asText());
        assertThat(properties.path("notValidBefore").asText()).isEqualTo("2013-08-01T12:00:00Z");
        assertThat(properties.path("notValidAfter").asText()).isEqualTo("2038-01-15T12:00:00Z");
        assertThat(properties.path("certificateFormat").asText()).isEqualTo("X.509");
        assertThat(properties.path("certificateExtension").asText()).isEqualTo("pem");
    }

    @Test
    void aComponentLimitedToOtherPackagesIsLeftOut() {
        assertThat(SbomChecks.componentRefs(describeDeb())).doesNotContain("pkg:maven/com.sun.winsw/winsw@2.0.1?classifier=bin&type=exe");
    }

    @Test
    void aComponentLimitedToThisPackageIsIncludedWithItsPurlAsRef() {
        JsonNode described = SbomPackage.describe(application(), "thingsboard", "4.4.0.1", zipPackage(), bundled());

        JsonNode winsw = component(described, "pkg:maven/com.sun.winsw/winsw@2.0.1?classifier=bin&type=exe");
        assertThat(winsw.path("group").asText()).isEqualTo("com.sun.winsw");
        assertThat(winsw.path("purl").asText()).isEqualTo("pkg:maven/com.sun.winsw/winsw@2.0.1?classifier=bin&type=exe");
        assertThat(Boms.graph(described).get("pkg:generic/thingsboard/thingsboard-windows@4.4.0.1")).contains(winsw.path("bom-ref").asText());
    }

    @Test
    void worksWithoutBundledComponents() {
        JsonNode described = SbomPackage.describe(application(), "thingsboard", "4.4.0.1", debPackage(), List.of());

        assertThat(Boms.graph(described).get(DEB_PURL)).containsExactly(APP_REF);
        assertThat(described.path("components")).hasSize(application().path("components").size() + 1);
    }

    @Test
    void resultIsValidAgainstTheCycloneDxSchema() throws IOException {
        assertThat(new JsonParser().validate(describeDeb(), Version.VERSION_16)).isEmpty();
    }

    @Test
    void sameInputsGiveTheSameOutput() {
        assertThat(describeDeb()).isEqualTo(describeDeb());
    }

    @Test
    void theSerialNumberChangesWithThePackageContents() throws IOException {
        String first = describeDeb().path("serialNumber").asText();
        Files.writeString(deb, "other deb contents");

        String second = describeDeb().path("serialNumber").asText();

        assertThat(first).startsWith("urn:uuid:");
        assertThat(second).startsWith("urn:uuid:").isNotEqualTo(first);
    }

    @Test
    void theSerialNumberDiffersFromTheApplicationSbom() {
        assertThat(describeDeb().path("serialNumber")).isNotEqualTo(application().path("serialNumber"));
    }

    @Test
    void inputIsNotModified() {
        ObjectNode application = application();

        SbomPackage.describe(application, "thingsboard", "4.4.0.1", debPackage(), bundled());

        assertThat(application).isEqualTo(application());
    }

    @Test
    void writesTheSbomNextToThePackage() throws IOException {
        Path applicationSbom = Files.writeString(tempDir.resolve("application.cdx.json"), application().toPrettyString());

        Path output = SbomPackage.writeFor(applicationSbom, "thingsboard", "4.4.0.1", debPackage(), bundled());

        assertThat(output).isEqualTo(tempDir.resolve("thingsboard.deb.cdx.json"));
        assertThat(Boms.MAPPER.readTree(output.toFile())).isEqualTo(describeDeb());
    }

    @Test
    void writesNothingWhenItFails() throws IOException {
        Path applicationSbom = Files.writeString(tempDir.resolve("application.cdx.json"), application().toPrettyString());
        Files.delete(bundle);

        assertThatThrownBy(() -> SbomPackage.writeFor(applicationSbom, "thingsboard", "4.4.0.1", debPackage(), bundled()))
                .isInstanceOf(SbomException.class);

        assertThat(tempDir.resolve("thingsboard.deb.cdx.json")).doesNotExist();
    }

    @Test
    void failsWhenThePackageFileIsMissing() throws IOException {
        Files.delete(deb);

        assertThatThrownBy(this::describeDeb)
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("Package file " + deb + " does not exist");
    }

    @Test
    void failsWhenThePackageFileIsEmpty() throws IOException {
        Files.writeString(deb, "");

        assertThatThrownBy(this::describeDeb)
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("is empty");
    }

    @Test
    void failsWhenABundledFileIsMissing() throws IOException {
        Files.delete(bundle);

        assertThatThrownBy(this::describeDeb)
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("Bundled component gateway-management-extension@4.4.0.1 points to " + bundle + ", which does not exist");
    }

    @Test
    void failsWhenABundledDirectoryIsEmpty() throws IOException {
        Files.delete(registry.resolve("3.xml"));

        assertThatThrownBy(this::describeDeb)
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("points to an empty directory");
    }

    @Test
    void failsWhenACertificateFileIsNotACertificate() {
        List<BundledComponent> components = List.of(new BundledComponent("cryptographic-asset", "not a certificate", null, bundle.toFile()));

        assertThatThrownBy(() -> SbomPackage.describe(application(), "thingsboard", "4.4.0.1", debPackage(), components))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("which is not an X.509 certificate");
    }

    @Test
    void failsWhenACertificateHasNoFile() {
        List<BundledComponent> components = List.of(new BundledComponent("cryptographic-asset", "no file", null, null));

        assertThatThrownBy(() -> SbomPackage.describe(application(), "thingsboard", "4.4.0.1", debPackage(), components))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("needs a certificate file");
    }

    @Test
    void failsWhenABundledComponentClashesWithAnApplicationComponent() {
        String existing = Boms.mavenFixture().path("components").get(0).path("purl").asText();
        List<BundledComponent> components = List.of(new BundledComponent("library", "clash", "1.0", bundle.toFile()).purl(existing));

        assertThatThrownBy(() -> SbomPackage.describe(application(), "thingsboard", "4.4.0.1", debPackage(), components))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("clashes with a component that is already in the SBOM");
    }

    @Test
    void failsWhenThePackagePurlIsUsedByTheApplication() {
        PackageFile clash = new PackageFile("deb", deb.toFile(), APP_REF, false);

        assertThatThrownBy(() -> SbomPackage.describe(application(), "thingsboard", "4.4.0.1", clash, bundled()))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("is already used by a component of the application SBOM");
    }

    @Test
    void failsOnAnInvalidPurl() {
        PackageFile invalid = new PackageFile("deb", deb.toFile(), "thingsboard.deb", false);

        assertThatThrownBy(() -> SbomPackage.describe(application(), "thingsboard", "4.4.0.1", invalid, bundled()))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("Package deb has an invalid purl thingsboard.deb");
    }

    @Test
    void failsOnABlankVersion() {
        assertThatThrownBy(() -> SbomPackage.describe(application(), "thingsboard", " ", debPackage(), bundled()))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("Package version is blank");
    }

    @Test
    void failsOnAnInvalidApplicationSbom() {
        ObjectNode broken = application();
        broken.put("bomFormat", "SPDX");

        assertThatThrownBy(() -> SbomPackage.describe(broken, "thingsboard", "4.4.0.1", debPackage(), bundled()))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("Application SBOM is not a CycloneDX document");
    }

    @Test
    void configCheckAcceptsAValidConfiguration() {
        SbomPackage.checkConfig(List.of(debPackage(), zipPackage()), bundled());
    }

    @Test
    void configCheckRejectsDuplicatePackageIds() {
        assertThatThrownBy(() -> SbomPackage.checkConfig(List.of(debPackage(), debPackage()), bundled()))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("Package id deb is used more than once");
    }

    @Test
    void configCheckRejectsAComponentForAnUnknownPackage() {
        assertThatThrownBy(() -> SbomPackage.checkConfig(List.of(debPackage()), bundled()))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("refers to unknown package zip");
    }

    @Test
    void configCheckRejectsDuplicateComponents() {
        List<BundledComponent> twice = List.of(
                new BundledComponent("library", "same", "1.0", bundle.toFile()),
                new BundledComponent("library", "same", "1.0", bundle.toFile()));

        assertThatThrownBy(() -> SbomPackage.checkConfig(List.of(debPackage()), twice))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("Bundled component same@1.0 is declared more than once");
    }

    @Test
    void configCheckRejectsAComponentWithoutName() {
        List<BundledComponent> unnamed = List.of(new BundledComponent("library", " ", "1.0", bundle.toFile()));

        assertThatThrownBy(() -> SbomPackage.checkConfig(List.of(debPackage()), unnamed))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("A bundled component has no name");
    }

    @Test
    void configCheckRejectsAPackageWithoutPurl() {
        PackageFile noPurl = new PackageFile("deb", deb.toFile(), null, false);

        assertThatThrownBy(() -> SbomPackage.checkConfig(List.of(noPurl), List.of()))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("Package deb has no purl");
    }

    @Test
    void configCheckRejectsAnEmptyPackageList() {
        assertThatThrownBy(() -> SbomPackage.checkConfig(List.of(), List.of()))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("No packages configured");
    }

    static final String EXTENSION_REF = "pkg:github/thingsboard/gateway-management-extensions@a12065d71896d3da95d4d1001c8269bf31d90f24";
    static final String ECHARTS_REF = "pkg:npm/echarts@5.5.2-TB?download_url=https%3A%2F%2Fgithub.com%2Fthingsboard%2Fecharts%2Farchive%2F5.5.2-TB.tar.gz";
    static final String ZRENDER_REF = "pkg:npm/zrender@5.5.0";

    ObjectNode extensionSbom() {
        ObjectNode bom = Boms.bom("1.6", EXTENSION_REF);
        ObjectNode root = (ObjectNode) bom.path("metadata").path("component");
        root.put("type", "library").put("purl", EXTENSION_REF);
        root.putArray("hashes").addObject().put("alg", "SHA-256").put("content", sha("SHA-256", bundle));
        ((ObjectNode) bom.get("metadata")).putObject("tools").putArray("components").addObject()
                .put("type", "application").put("group", "@cyclonedx").put("name", "cyclonedx-npm").put("version", "6.0.1");
        Boms.component(bom, ECHARTS_REF, ECHARTS_REF);
        Boms.component(bom, ZRENDER_REF, ZRENDER_REF);
        Boms.dependency(bom, EXTENSION_REF, ECHARTS_REF);
        Boms.dependency(bom, ECHARTS_REF, ZRENDER_REF);
        Boms.dependency(bom, ZRENDER_REF);
        return bom;
    }

    BundledComponent extension(ObjectNode sbom) throws IOException {
        Path file = tempDir.resolve("extension.cdx.json");
        Files.writeString(file, Boms.MAPPER.writeValueAsString(sbom));
        return new BundledComponent("library", null, null, bundle.toFile()).sbom(file.toFile());
    }

    ObjectNode describeDebWith(BundledComponent component) {
        return SbomPackage.describe(application(), "thingsboard", "4.4.0.1", debPackage(), List.of(component));
    }

    @Test
    void aComponentWithItsOwnSbomBringsItsRootAndComponents() throws IOException {
        JsonNode described = describeDebWith(extension(extensionSbom()));

        JsonNode root = component(described, EXTENSION_REF);
        assertThat(root.path("purl").asText()).isEqualTo(EXTENSION_REF);
        assertThat(root.path("hashes")).isEqualTo(Boms.MAPPER.readTree("""
                [{"alg":"SHA-256","content":"%s"},{"alg":"SHA-512","content":"%s"}]""".formatted(sha("SHA-256", bundle), sha("SHA-512", bundle))));
        assertThat(component(described, ECHARTS_REF).path("purl").asText()).isEqualTo(ECHARTS_REF);
        assertThat(component(described, ZRENDER_REF).path("purl").asText()).isEqualTo(ZRENDER_REF);
        assertThat(Boms.graph(described).get(DEB_PURL)).containsExactlyInAnyOrder(APP_REF, EXTENSION_REF);
        assertThat(Boms.graph(described).get(EXTENSION_REF)).containsExactly(ECHARTS_REF);
        assertThat(Boms.graph(described).get(ECHARTS_REF)).containsExactly(ZRENDER_REF);
        assertThat(Boms.reachable(described, DEB_PURL)).containsAll(SbomChecks.componentRefs(described));
        assertThat(new JsonParser().validate(described, Version.VERSION_16)).isEmpty();
    }

    @Test
    void theToolsOfAComponentSbomAreAdded() throws IOException {
        JsonNode tools = describeDebWith(extension(extensionSbom())).path("metadata").path("tools").path("components");

        List<String> names = new ArrayList<>();
        tools.forEach(tool -> names.add(tool.path("name").asText()));
        assertThat(names).contains("cyclonedx-npm");
        application().path("metadata").path("tools").path("components").forEach(tool -> assertThat(names).contains(tool.path("name").asText()));
    }

    @Test
    void aComponentSbomComponentAlreadyInTheApplicationIsNotDuplicated() throws IOException {
        JsonNode existing = application().path("components").get(0);
        ObjectNode sbom = extensionSbom();
        Boms.component(sbom, existing.path("bom-ref").asText(), existing.path("purl").asText());
        ((ObjectNode) sbom.path("dependencies").get(0)).withArrayProperty("dependsOn").add(existing.path("bom-ref").asText());

        JsonNode described = describeDebWith(extension(sbom));

        List<String> refs = new ArrayList<>();
        described.path("components").forEach(component -> refs.add(component.path("bom-ref").asText()));
        assertThat(refs).containsOnlyOnce(existing.path("bom-ref").asText());
        assertThat(Boms.graph(described).get(EXTENSION_REF)).contains(existing.path("bom-ref").asText());
    }

    @Test
    void failsWhenAComponentSbomRefClashesWithADifferentComponent() throws IOException {
        JsonNode existing = application().path("components").get(0);
        ObjectNode sbom = extensionSbom();
        Boms.component(sbom, existing.path("bom-ref").asText(), "pkg:npm/something-else@1.0.0");
        ((ObjectNode) sbom.path("dependencies").get(0)).withArrayProperty("dependsOn").add(existing.path("bom-ref").asText());
        BundledComponent component = extension(sbom);

        assertThatThrownBy(() -> describeDebWith(component))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("clashes with a different component that is already in the SBOM");
    }

    @Test
    void failsWhenTheComponentSbomWasBuiltForAnotherFile() throws IOException {
        BundledComponent component = extension(extensionSbom());
        Files.writeString(bundle, "console.log('another build');");

        assertThatThrownBy(() -> describeDebWith(component))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("copy the SBOM that was built together with this file");
    }

    @Test
    void failsWhenTheComponentSbomHasNoSha256() throws IOException {
        ObjectNode sbom = extensionSbom();
        ((ObjectNode) sbom.path("metadata").path("component")).remove("hashes");
        BundledComponent component = extension(sbom);

        assertThatThrownBy(() -> describeDebWith(component))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("does not give the SHA-256");
    }

    @Test
    void failsWhenTheComponentSbomUsesAnotherSpecVersion() throws IOException {
        ObjectNode sbom = extensionSbom();
        sbom.put("specVersion", "1.5");
        BundledComponent component = extension(sbom);

        assertThatThrownBy(() -> describeDebWith(component))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("is CycloneDX 1.5, but the SBOM it goes into is 1.6");
    }

    @Test
    void failsWhenAComponentSbomHasUnreachableComponents() throws IOException {
        ObjectNode sbom = extensionSbom();
        Boms.component(sbom, "pkg:npm/orphan@1.0.0", "pkg:npm/orphan@1.0.0");
        BundledComponent component = extension(sbom);

        assertThatThrownBy(() -> describeDebWith(component))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("has components that its root does not depend on: [pkg:npm/orphan@1.0.0]");
    }

    @Test
    void failsWhenTheComponentSbomIsMissing() {
        BundledComponent component = new BundledComponent("library", null, null, bundle.toFile()).sbom(tempDir.resolve("missing.cdx.json").toFile());

        assertThatThrownBy(() -> describeDebWith(component))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("does not exist");
    }

    @Test
    void configCheckRejectsAComponentSbomWithDetailsOfItsOwn() throws IOException {
        BundledComponent component = extension(extensionSbom()).license("MIT");

        assertThatThrownBy(() -> SbomPackage.checkConfig(List.of(debPackage()), List.of(component)))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("takes its details from its SBOM and must not set [license]");
    }

    @Test
    void configCheckRejectsImageOnlyDirectories() {
        BundledComponent component = new BundledComponent("library", "app", "1.0", bundle.toFile()).installDir("/usr/share/app");

        assertThatThrownBy(() -> SbomPackage.checkConfig(List.of(debPackage()), List.of(component)))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("sets installDir or bundleDir, which only apply to image SBOMs");
    }

    @Test
    void configCheckRejectsAComponentSbomWithoutFile() {
        BundledComponent component = new BundledComponent("library", null, null, null).sbom(tempDir.resolve("extension.cdx.json").toFile());

        assertThatThrownBy(() -> SbomPackage.checkConfig(List.of(debPackage()), List.of(component)))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("has an SBOM but no file to check it against");
    }

    static JsonNode component(JsonNode bom, String ref) {
        for (JsonNode component : bom.path("components")) {
            if (component.path("bom-ref").asText().equals(ref)) {
                return component;
            }
        }
        throw new AssertionError("No component " + ref);
    }

    static String sha(String algorithm, Path file) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance(algorithm).digest(Files.readAllBytes(file)));
        } catch (IOException | NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

}
