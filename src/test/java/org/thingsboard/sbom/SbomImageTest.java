package org.thingsboard.sbom;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.cyclonedx.Version;
import org.cyclonedx.parsers.JsonParser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SbomImageTest {

    static final String DIGEST = "sha256:40c308b73fdf1f4fd3375881e6812825b42906b13cfef47e00c7dbe774391778";
    static final String OTHER_DIGEST = "sha256:a99a84223d27deef5f4c21a5ce0ef4c4772727ee3d0348c0e0fa3c385dc2ecb0";
    static final String IMAGE_REF = "pkg:docker/thingsboard/tb-mqtt-transport@sha256%3A40c308b73fdf1f4fd3375881e6812825b42906b13cfef47e00c7dbe774391778?arch=amd64";
    static final String DEB_PURL = "pkg:deb/thingsboard/tb-mqtt-transport@4.4.1-1?arch=all";

    static final String SCAN_ROOT = "ba5a4903c5069929";
    static final String OS = "os:debian@13.7";
    static final String LIBC = "pkg:deb/debian/libc6@2.41-12?arch=amd64&distro=debian-13.7&package-id=2dc9b457970cbedd";
    static final String JRE = "pkg:deb/debian/openjdk-25-jre-headless@25.0.4?arch=amd64&distro=debian-13.7&package-id=4e6fde7cc87e24d4";
    static final String CURL = "pkg:deb/debian/curl@8.14.1-2?arch=amd64&distro=debian-13.7&package-id=1b2c3d4e5f607182";
    static final String SCANNED_DEB = "pkg:deb/debian/tb-mqtt-transport@4.4.1-1?arch=all&distro=debian-13.7&package-id=c84ed22d92ad12f4";

    @TempDir
    Path tempDir;

    Path deb;
    Path packageSbom;

    @BeforeEach
    void createPackage() throws IOException {
        deb = Files.writeString(tempDir.resolve("tb-mqtt-transport.deb"), "deb contents");
        Path applicationSbom = Files.writeString(tempDir.resolve("application.cdx.json"), SbomPackageTest.application().toPrettyString());
        packageSbom = SbomPackage.writeFor(applicationSbom, "tb-mqtt-transport", "4.4.1", new PackageFile("deb", deb.toFile(), DEB_PURL, false), List.of());
    }

    static ObjectNode osSbom() {
        ObjectNode bom = Boms.bom("1.6", SCAN_ROOT);
        ObjectNode metadata = (ObjectNode) bom.get("metadata");
        metadata.put("timestamp", "2026-11-06T15:28:27+02:00");
        metadata.putObject("tools").putArray("components").addObject()
                .put("type", "application").put("author", "anchore").put("name", "syft").put("version", "1.57.0");
        ((ObjectNode) metadata.get("component")).put("type", "container").put("name", "thingsboard/tb-mqtt-transport").put("version", DIGEST);
        ArrayNode components = (ArrayNode) bom.get("components");
        components.addObject().put("bom-ref", OS).put("type", "operating-system").put("name", "debian").put("version", "13.7");
        osPackage(bom, LIBC, "libc6", "2.41-12");
        osPackage(bom, JRE, "openjdk-25-jre-headless", "25.0.4");
        osPackage(bom, CURL, "curl", "8.14.1-2");
        osPackage(bom, SCANNED_DEB, "tb-mqtt-transport", "4.4.1-1");
        Boms.dependency(bom, CURL, LIBC);
        Boms.dependency(bom, JRE, LIBC);
        Boms.dependency(bom, SCANNED_DEB, JRE);
        return bom;
    }

    static ObjectNode osPackage(ObjectNode bom, String ref, String name, String version) {
        ObjectNode component = ((ArrayNode) bom.get("components")).addObject()
                .put("bom-ref", ref).put("type", "library").put("name", name).put("version", version)
                .put("purl", ref.replaceAll("&package-id=[0-9a-f]+", ""));
        component.putArray("properties").addObject().put("name", "syft:package:foundBy").put("value", "dpkg-db-cataloger");
        return component;
    }

    static SbomImage.Image image() {
        return new SbomImage.Image("thingsboard/tb-mqtt-transport", "4.4.1", DIGEST, "amd64");
    }

    BundledComponent debComponent() {
        return new BundledComponent("library", null, null, deb.toFile()).sbom(packageSbom.toFile());
    }

    ObjectNode describe() {
        return SbomImage.describe(osSbom(), image(), List.of(debComponent()));
    }

    JsonNode packageSbom() throws IOException {
        return Boms.MAPPER.readTree(packageSbom.toFile());
    }

    @Test
    void theImageIsTheRootComponent() {
        JsonNode root = describe().path("metadata").path("component");

        assertThat(root.path("type").asText()).isEqualTo("container");
        assertThat(root.path("bom-ref").asText()).isEqualTo(IMAGE_REF);
        assertThat(root.path("purl").asText()).isEqualTo(IMAGE_REF);
        assertThat(root.path("group").asText()).isEqualTo("thingsboard");
        assertThat(root.path("name").asText()).isEqualTo("tb-mqtt-transport");
        assertThat(root.path("version").asText()).isEqualTo("4.4.1");
        assertThat(root.path("hashes")).hasSize(1);
        assertThat(root.path("hashes").get(0).path("alg").asText()).isEqualTo("SHA-256");
        assertThat(root.path("hashes").get(0).path("content").asText()).isEqualTo(DIGEST.substring("sha256:".length()));
    }

    @Test
    void theImageTakesItsManufacturerFromThePackage() throws IOException {
        JsonNode root = describe().path("metadata").path("component");

        assertThat(root.path("manufacturer")).isNotEmpty().isEqualTo(packageSbom().path("metadata").path("component").path("manufacturer"));
    }

    @Test
    void sbomMetadataComesFromThePackageAndTheScan() throws IOException {
        JsonNode packageMetadata = packageSbom().path("metadata");
        JsonNode metadata = describe().path("metadata");

        assertThat(metadata.path("manufacturer")).isEqualTo(packageMetadata.path("manufacturer"));
        assertThat(metadata.path("supplier")).isEqualTo(packageMetadata.path("supplier"));
        assertThat(metadata.path("lifecycles")).isEqualTo(packageMetadata.path("lifecycles"));
        assertThat(metadata.has("timestamp")).isFalse();
        assertThat(metadata.has("properties")).isFalse();
        List<String> tools = new ArrayList<>();
        metadata.path("tools").path("components").forEach(tool -> tools.add(tool.path("name").asText()));
        assertThat(tools).contains("syft");
        packageMetadata.path("tools").path("components").forEach(tool -> assertThat(tools).contains(tool.path("name").asText()));
    }

    @Test
    void theScannedPackageIsReplacedByThePackageSbom() throws IOException {
        JsonNode described = describe();

        Set<String> refs = SbomChecks.componentRefs(described);
        assertThat(refs).doesNotContain(SCANNED_DEB).contains(DEB_PURL);
        assertThat(SbomPackageTest.component(described, DEB_PURL)).isEqualTo(packageSbom().path("metadata").path("component"));
        assertThat(Boms.graph(described)).doesNotContainKey(SCANNED_DEB);
        Boms.graph(described).values().forEach(targets -> assertThat(targets).doesNotContain(SCANNED_DEB));
    }

    @Test
    void thePackageKeepsTheOsDependenciesTheScanFoundAndItsOwn() throws IOException {
        JsonNode described = describe();

        assertThat(Boms.graph(described).get(DEB_PURL)).containsExactlyInAnyOrder(JRE, SbomPackageTest.APP_REF);
        assertThat(Boms.graph(packageSbom()).get(DEB_PURL)).containsExactly(SbomPackageTest.APP_REF);
    }

    @Test
    void theImageDependsOnTheTopLevelOsComponentsAndThePackage() {
        JsonNode described = describe();

        assertThat(Boms.graph(described).get(IMAGE_REF)).containsExactlyInAnyOrder(OS, CURL, DEB_PURL);
    }

    @Test
    void theScanRootIsDropped() {
        ObjectNode os = osSbom();
        Boms.dependency(os, SCAN_ROOT, OS, LIBC);

        JsonNode described = SbomImage.describe(os, image(), List.of(debComponent()));

        assertThat(SbomChecks.componentRefs(described)).doesNotContain(SCAN_ROOT);
        assertThat(Boms.graph(described)).doesNotContainKey(SCAN_ROOT);
        assertThat(Boms.graph(described).get(IMAGE_REF)).containsExactlyInAnyOrder(OS, CURL, DEB_PURL);
    }

    @Test
    void osComponentsAreKeptUnchanged() {
        JsonNode described = describe();

        List<JsonNode> components = new ArrayList<>();
        described.path("components").forEach(components::add);
        osSbom().path("components").forEach(component -> {
            if (!component.path("bom-ref").asText().equals(SCANNED_DEB)) {
                assertThat(components).contains(component);
            }
        });
    }

    @Test
    void everythingInThePackageSbomIsKept() throws IOException {
        JsonNode packageSbom = packageSbom();
        JsonNode described = describe();

        List<JsonNode> components = new ArrayList<>();
        described.path("components").forEach(components::add);
        packageSbom.path("components").forEach(component -> assertThat(components).contains(component));
        packageSbom.path("dependencies").forEach(dependency ->
                assertThat(Boms.graph(described).get(dependency.path("ref").asText()))
                        .containsAll(Boms.graph(packageSbom).get(dependency.path("ref").asText())));
    }

    @Test
    void everyComponentIsReachableFromTheImage() {
        JsonNode described = describe();

        assertThat(Boms.reachable(described, IMAGE_REF)).containsAll(SbomChecks.componentRefs(described));
        assertThat(SbomChecks.componentRefs(described)).hasSize(osSbom().path("components").size() - 1 + packageComponentCount());
    }

    @Test
    void aBundledComponentThatIsNotAnOsPackageIsAddedNextToTheOsPackages() throws IOException {
        SbomPackageTest extensionTest = new SbomPackageTest();
        extensionTest.tempDir = tempDir;
        extensionTest.createFiles();
        BundledComponent extension = extensionTest.extension(extensionTest.extensionSbom());

        JsonNode described = SbomImage.describe(osSbom(), image(), List.of(debComponent(), extension));

        assertThat(Boms.graph(described).get(IMAGE_REF)).containsExactlyInAnyOrder(OS, CURL, DEB_PURL, SbomPackageTest.EXTENSION_REF);
        assertThat(SbomChecks.componentRefs(described)).contains(SbomPackageTest.EXTENSION_REF, SbomPackageTest.ECHARTS_REF, SbomPackageTest.ZRENDER_REF);
        assertThat(Boms.reachable(described, IMAGE_REF)).containsAll(SbomChecks.componentRefs(described));
    }

    @Test
    void resultIsValidAgainstTheCycloneDxSchema() throws IOException {
        assertThat(new JsonParser().validate(describe(), Version.VERSION_16)).isEmpty();
    }

    @Test
    void sameInputsGiveTheSameOutput() {
        assertThat(describe()).isEqualTo(describe());
    }

    @Test
    void eachArchitectureGetsItsOwnSerialNumber() {
        String amd64 = describe().path("serialNumber").asText();
        String arm64 = SbomImage.describe(osSbom(), new SbomImage.Image("thingsboard/tb-mqtt-transport", "4.4.1", OTHER_DIGEST, "arm64"),
                List.of(debComponent())).path("serialNumber").asText();

        assertThat(amd64).startsWith("urn:uuid:");
        assertThat(arm64).startsWith("urn:uuid:").isNotEqualTo(amd64);
    }

    @Test
    void inputIsNotModified() {
        ObjectNode os = osSbom();

        SbomImage.describe(os, image(), List.of(debComponent()));

        assertThat(os).isEqualTo(osSbom());
    }

    @Test
    void writesTheSbom() throws IOException {
        Path os = Files.writeString(tempDir.resolve("os.cdx.json"), osSbom().toPrettyString());
        Path output = tempDir.resolve("image").resolve("image-amd64.cdx.json");

        SbomImage.write(os, image(), List.of(debComponent()), output);

        assertThat(Boms.MAPPER.readTree(output.toFile())).isEqualTo(describe());
    }

    @Test
    void writesNothingWhenItFails() throws IOException {
        Path os = Files.writeString(tempDir.resolve("os.cdx.json"), osSbom().toPrettyString());
        Path output = tempDir.resolve("image-amd64.cdx.json");
        Files.writeString(deb, "another deb build");

        assertThatThrownBy(() -> SbomImage.write(os, image(), List.of(debComponent()), output)).isInstanceOf(SbomException.class);

        assertThat(output).doesNotExist();
    }

    @Test
    void failsWhenThePackageSbomWasBuiltForAnotherDeb() throws IOException {
        Files.writeString(deb, "another deb build");

        assertThatThrownBy(this::describe)
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("copy the SBOM that was built together with this file");
    }

    @Test
    void failsWhenTheImageDoesNotInstallThePackage() {
        ObjectNode os = osSbom();
        removeComponent(os, SCANNED_DEB);

        assertThatThrownBy(() -> SbomImage.describe(os, image(), List.of(debComponent())))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("The OS SBOM should list tb-mqtt-transport as one installed deb package, but lists it 0 times");
    }

    @Test
    void failsWhenTheScanListsThePackageTwice() {
        ObjectNode os = osSbom();
        osPackage(os, SCANNED_DEB.replace("c84ed22d92ad12f4", "0000000000000000"), "tb-mqtt-transport", "4.4.1-1");

        assertThatThrownBy(() -> SbomImage.describe(os, image(), List.of(debComponent())))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("but lists it 2 times");
    }

    @Test
    void aPackageOfAnotherTypeWithTheSameNameIsNotReplaced() {
        ObjectNode os = osSbom();
        String rpm = "pkg:rpm/redhat/tb-mqtt-transport@4.4.1-1?arch=noarch";
        Boms.component(os, rpm, rpm).put("name", "tb-mqtt-transport");

        JsonNode described = SbomImage.describe(os, image(), List.of(debComponent()));

        assertThat(SbomChecks.componentRefs(described)).contains(rpm).doesNotContain(SCANNED_DEB);
    }

    @Test
    void failsWhenTheImageInstallsAnotherVersionOfThePackage() {
        ObjectNode os = osSbom();
        removeComponent(os, SCANNED_DEB);
        osPackage(os, SCANNED_DEB.replace("4.4.1-1", "4.4.0-1"), "tb-mqtt-transport", "4.4.0-1");

        assertThatThrownBy(() -> SbomImage.describe(os, image(), List.of(debComponent())))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("The image installs tb-mqtt-transport 4.4.0-1, but the SBOM of " + DEB_PURL + " is for 4.4.1-1");
    }

    @Test
    void thePackageIsMatchedByThePurlNameNotTheComponentName() throws IOException {
        Path applicationSbom = Files.writeString(tempDir.resolve("application.cdx.json"), SbomPackageTest.application().toPrettyString());
        SbomPackage.writeFor(applicationSbom, "mqtt", "4.4.1", new PackageFile("deb", deb.toFile(), DEB_PURL, false), List.of());

        JsonNode described = describe();

        assertThat(SbomChecks.componentRefs(described)).contains(DEB_PURL).doesNotContain(SCANNED_DEB);
    }

    @Test
    void aDependencyCycleNothingElseDependsOnIsReachableFromTheImage() {
        ObjectNode os = osSbom();
        String jre17 = "pkg:deb/debian/openjdk-17-jre-headless@17.0.16?arch=amd64&distro=debian-13.7&package-id=1111111111111111";
        String certificates = "pkg:deb/debian/ca-certificates-java@20240118?arch=all&distro=debian-13.7&package-id=2222222222222222";
        osPackage(os, jre17, "openjdk-17-jre-headless", "17.0.16");
        osPackage(os, certificates, "ca-certificates-java", "20240118");
        Boms.dependency(os, jre17, certificates);
        Boms.dependency(os, certificates, jre17);

        JsonNode described = SbomImage.describe(os, image(), List.of(debComponent()));

        assertThat(Boms.graph(described).get(IMAGE_REF)).hasSize(4).containsAnyOf(jre17, certificates);
        assertThat(Boms.reachable(described, IMAGE_REF)).containsAll(SbomChecks.componentRefs(described));
    }

    @Test
    void failsWhenTheScanAlsoCatalogedWhatThePackageInstalls() {
        ObjectNode os = osSbom();
        String jar = "pkg:maven/org.thingsboard/application@4.4.1-SNAPSHOT";
        Boms.component(os, "f00dfeedcafebabe", jar);

        assertThatThrownBy(() -> SbomImage.describe(os, image(), List.of(debComponent())))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("The OS SBOM also lists components that come from the bundled SBOMs: [" + jar + "]")
                .hasMessageContaining("exclude the directories the bundled packages install to from the OS scan");
    }

    @Test
    void failsWhenAnOsComponentRefClashesWithABundledComponent() {
        ObjectNode os = osSbom();
        Boms.component(os, SbomPackageTest.APP_REF, "pkg:generic/something-else@1.0");

        assertThatThrownBy(() -> SbomImage.describe(os, image(), List.of(debComponent())))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("Component " + SbomPackageTest.APP_REF + " from the SBOM of " + DEB_PURL + " clashes with a different component");
    }

    @Test
    void failsWithoutBundledComponents() {
        assertThatThrownBy(() -> SbomImage.describe(osSbom(), image(), List.of()))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("No bundled components configured");
    }

    @Test
    void aComponentWithoutSbomIsAddedAsConfigured() {
        BundledComponent chrome = new BundledComponent("application", "chrome-for-testing", "156.0.8078.4", null)
                .purl("pkg:generic/google/chrome-for-testing@156.0.8078.4?os=linux").license("BSD-3-Clause");

        JsonNode described = SbomImage.describe(osSbom(), image(), List.of(debComponent(), chrome));

        JsonNode component = SbomPackageTest.component(described, "pkg:generic/google/chrome-for-testing@156.0.8078.4?os=linux");
        assertThat(component.path("version").asText()).isEqualTo("156.0.8078.4");
        assertThat(component.has("hashes")).isFalse();
        assertThat(Boms.graph(described).get(IMAGE_REF)).contains("pkg:generic/google/chrome-for-testing@156.0.8078.4?os=linux");
    }

    @Test
    void failsWhenThePackageSbomUsesAnotherSpecVersion() {
        ObjectNode os = osSbom();
        os.put("specVersion", "1.5");

        assertThatThrownBy(() -> SbomImage.describe(os, image(), List.of(debComponent())))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("is CycloneDX 1.6, but the SBOM it goes into is 1.5");
    }

    @Test
    void failsOnAnInvalidOsSbom() {
        ObjectNode os = osSbom();
        os.put("bomFormat", "SPDX");

        assertThatThrownBy(() -> SbomImage.describe(os, image(), List.of(debComponent())))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("OS SBOM is not a CycloneDX document");
    }

    @Test
    void failsOnARepositoryWithoutNamespace() {
        SbomImage.Image image = new SbomImage.Image("tb-mqtt-transport", "4.4.1", DIGEST, "amd64");

        assertThatThrownBy(() -> SbomImage.describe(osSbom(), image, List.of(debComponent())))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("Image repository tb-mqtt-transport must be <namespace>/<name>");
    }

    @Test
    void failsOnARepositoryWithARegistryOrTag() {
        for (String repository : List.of("docker.io/thingsboard/tb-mqtt-transport", "thingsboard/tb-mqtt-transport:4.4.1", "ThingsBoard/tb-mqtt-transport")) {
            SbomImage.Image image = new SbomImage.Image(repository, "4.4.1", DIGEST, "amd64");

            assertThatThrownBy(() -> SbomImage.describe(osSbom(), image, List.of(debComponent())))
                    .isInstanceOf(SbomException.class)
                    .hasMessageContaining("must be <namespace>/<name>");
        }
    }

    @Test
    void failsOnADigestThatIsNotSha256() {
        for (String digest : List.of("40c308b73fdf1f4fd3375881e6812825b42906b13cfef47e00c7dbe774391778", "sha256:40c308b7", "sha512:" + "0".repeat(128))) {
            SbomImage.Image image = new SbomImage.Image("thingsboard/tb-mqtt-transport", "4.4.1", digest, "amd64");

            assertThatThrownBy(() -> SbomImage.describe(osSbom(), image, List.of(debComponent())))
                    .isInstanceOf(SbomException.class)
                    .hasMessageContaining("must be sha256:<64 hex digits>");
        }
    }

    @Test
    void failsOnABlankTag() {
        SbomImage.Image image = new SbomImage.Image("thingsboard/tb-mqtt-transport", " ", DIGEST, "amd64");

        assertThatThrownBy(() -> SbomImage.describe(osSbom(), image, List.of(debComponent())))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("Image tag is blank");
    }

    @Test
    void failsOnABlankArchitecture() {
        SbomImage.Image image = new SbomImage.Image("thingsboard/tb-mqtt-transport", "4.4.1", DIGEST, "");

        assertThatThrownBy(() -> SbomImage.describe(osSbom(), image, List.of(debComponent())))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("Image architecture is blank");
    }

    int packageComponentCount() {
        try {
            return packageSbom().path("components").size() + 1;
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    static void removeComponent(ObjectNode bom, String ref) {
        ArrayNode components = (ArrayNode) bom.get("components");
        for (int i = 0; i < components.size(); i++) {
            if (components.get(i).path("bom-ref").asText().equals(ref)) {
                components.remove(i);
                break;
            }
        }
        ArrayNode dependencies = (ArrayNode) bom.get("dependencies");
        for (int i = dependencies.size() - 1; i >= 0; i--) {
            if (dependencies.get(i).path("ref").asText().equals(ref)) {
                dependencies.remove(i);
            }
        }
    }

}
