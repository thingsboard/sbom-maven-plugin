package org.thingsboard.sbom;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.cyclonedx.Version;
import org.cyclonedx.parsers.JsonParser;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SbomImageNpmTest {

    static final String APP_DIR = "/usr/share/tb-js-executor";
    static final String APP_REF = "pkg:maven/org.thingsboard.msa/js-executor@4.4.1";
    static final String IMAGE_REF = "pkg:docker/thingsboard/tb-js-executor@sha256%3A40c308b73fdf1f4fd3375881e6812825b42906b13cfef47e00c7dbe774391778?arch=arm64";
    static final String EXPRESS = "pkg:npm/express@5.1.0";
    static final String LZ4 = "pkg:npm/%40antoniomuso/lz4-napi@2.10.0";
    static final String LZ4_X64 = "pkg:npm/%40antoniomuso/lz4-napi-linux-x64-gnu@2.10.0";
    static final String LZ4_ARM64 = "pkg:npm/%40antoniomuso/lz4-napi-linux-arm64-gnu@2.10.0";
    static final String NPM = "pkg:npm/npm@10.9.4";

    static final String UI_REF = "pkg:maven/org.thingsboard/ui-ngx@4.4.1";
    static final String HUGERTE = "pkg:npm/hugerte@1.0.14";
    static final String ANGULAR = "pkg:npm/%40angular/core@20.3.4";

    @TempDir
    Path tempDir;

    static ObjectNode appSbom() {
        ObjectNode bom = Boms.bom("1.6", APP_REF);
        ObjectNode metadata = (ObjectNode) bom.get("metadata");
        ((ObjectNode) metadata.get("component")).put("purl", APP_REF).putObject("manufacturer").put("name", "ThingsBoard, Inc.");
        metadata.putObject("supplier").put("name", "ThingsBoard, Inc.");
        metadata.putObject("tools").putArray("components").addObject()
                .put("type", "library").put("group", "@cyclonedx").put("name", "cyclonedx-library").put("version", "10.3.0");
        installed(bom, EXPRESS, "node_modules/express");
        installed(bom, LZ4, "node_modules/@antoniomuso/lz4-napi");
        installed(bom, LZ4_X64, "node_modules/@antoniomuso/lz4-napi-linux-x64-gnu").put("scope", "optional");
        Boms.component(bom, LZ4_ARM64, LZ4_ARM64).put("scope", "optional");
        Boms.dependency(bom, APP_REF, EXPRESS, LZ4);
        Boms.dependency(bom, EXPRESS);
        Boms.dependency(bom, LZ4, LZ4_X64, LZ4_ARM64);
        Boms.dependency(bom, LZ4_X64);
        Boms.dependency(bom, LZ4_ARM64);
        return bom;
    }

    static ObjectNode installed(ObjectNode bom, String purl, String path) {
        ObjectNode component = Boms.component(bom, purl, purl);
        component.putArray("properties").addObject().put("name", "cdx:npm:package:path").put("value", path);
        return component;
    }

    static ObjectNode uiSbom() {
        ObjectNode bom = Boms.bom("1.6", UI_REF);
        ((ObjectNode) bom.path("metadata").path("component")).put("type", "library").put("purl", UI_REF);
        Boms.component(bom, HUGERTE, HUGERTE);
        Boms.component(bom, ANGULAR, ANGULAR);
        Boms.dependency(bom, UI_REF, HUGERTE, ANGULAR);
        Boms.dependency(bom, HUGERTE);
        Boms.dependency(bom, ANGULAR);
        return bom;
    }

    static ObjectNode scan(String... nativeModules) {
        ObjectNode bom = Boms.bom("1.6", "ba5a4903c5069929");
        ((ObjectNode) bom.path("metadata").path("component")).put("type", "container");
        ((ObjectNode) bom.get("metadata")).putObject("tools").putArray("components").addObject()
                .put("type", "application").put("author", "anchore").put("name", "syft").put("version", "1.57.0");
        ((ArrayNode) bom.get("components")).addObject().put("bom-ref", "os:debian@12.12").put("type", "operating-system").put("name", "debian").put("version", "12.12");
        scanned(bom, "pkg:npm/thingsboard-js-executor@4.4.1", APP_DIR + "/package.json");
        scanned(bom, EXPRESS, APP_DIR + "/node_modules/express/package.json");
        scanned(bom, LZ4, APP_DIR + "/node_modules/@antoniomuso/lz4-napi/package.json");
        for (String nativeModule : nativeModules) {
            scanned(bom, nativeModule, APP_DIR + "/node_modules/@antoniomuso/" + nativeModule.substring(nativeModule.indexOf("lz4-napi-"), nativeModule.indexOf('@', 10)) + "/package.json");
        }
        scanned(bom, NPM, "/usr/local/lib/node_modules/npm/package.json");
        return bom;
    }

    static String scanned(ObjectNode bom, String purl, String location) {
        String ref = purl + "?package-id=" + Integer.toHexString(location.hashCode());
        ObjectNode component = Boms.component(bom, ref, purl);
        ArrayNode properties = component.putArray("properties");
        properties.addObject().put("name", "syft:package:foundBy").put("value", "javascript-package-cataloger");
        properties.addObject().put("name", "syft:location:0:path").put("value", location);
        return ref;
    }

    static SbomImage.Image image(String architecture) {
        return new SbomImage.Image("thingsboard/tb-js-executor", "4.4.1", "sha256:40c308b73fdf1f4fd3375881e6812825b42906b13cfef47e00c7dbe774391778", architecture);
    }

    BundledComponent app(ObjectNode sbom) throws IOException {
        Path file = Files.writeString(tempDir.resolve("js-executor.cdx.json"), sbom.toPrettyString());
        return new BundledComponent("application", null, null, null).sbom(file.toFile()).installDir(APP_DIR);
    }

    BundledComponent ui(ObjectNode sbom, String dir) throws IOException {
        Path file = Files.writeString(tempDir.resolve("ui-ngx.cdx.json"), sbom.toPrettyString());
        return new BundledComponent("library", null, null, null).sbom(file.toFile()).bundleDir(dir);
    }

    ObjectNode describeArm64() throws IOException {
        return SbomImage.describe(scan(LZ4_ARM64), image("arm64"), List.of(app(appSbom())));
    }

    @Test
    void theInstalledApplicationReplacesWhatTheScanFoundInItsDirectory() throws IOException {
        JsonNode described = describeArm64();

        Set<String> refs = SbomChecks.componentRefs(described);
        assertThat(refs).contains(APP_REF, EXPRESS, LZ4, LZ4_ARM64, NPM + "?package-id=" + Integer.toHexString("/usr/local/lib/node_modules/npm/package.json".hashCode()));
        assertThat(refs).noneMatch(ref -> ref.contains("thingsboard-js-executor") || ref.startsWith(EXPRESS + "?") || ref.startsWith(LZ4 + "?"));
        assertThat(Boms.graph(described).get(IMAGE_REF)).contains(APP_REF);
        assertThat(Boms.graph(described).get(APP_REF)).containsExactlyInAnyOrder(EXPRESS, LZ4);
        assertThat(Boms.reachable(described, IMAGE_REF)).containsAll(refs);
    }

    @Test
    void optionalPackagesThisArchitectureDoesNotInstallAreDropped() throws IOException {
        JsonNode arm64 = describeArm64();
        JsonNode amd64 = SbomImage.describe(scan(LZ4_X64), image("amd64"), List.of(app(appSbom())));

        assertThat(SbomChecks.componentRefs(arm64)).contains(LZ4_ARM64).doesNotContain(LZ4_X64);
        assertThat(Boms.graph(arm64).get(LZ4)).containsExactly(LZ4_ARM64);
        assertThat(SbomChecks.componentRefs(amd64)).contains(LZ4_X64).doesNotContain(LZ4_ARM64);
        assertThat(Boms.graph(amd64).get(LZ4)).containsExactly(LZ4_X64);
        assertThat(Boms.graph(amd64)).doesNotContainKey(LZ4_ARM64);
    }

    @Test
    void theComponentsKeepWhatOurSbomSaysAboutThem() throws IOException {
        ObjectNode sbom = appSbom();
        ((ObjectNode) sbom.get("components").get(0)).putArray("licenses").addObject().put("expression", "MIT");

        JsonNode described = SbomImage.describe(scan(LZ4_ARM64), image("arm64"), List.of(app(sbom)));

        assertThat(SbomPackageTest.component(described, EXPRESS)).isEqualTo(sbom.get("components").get(0));
        assertThat(SbomPackageTest.component(described, APP_REF).path("purl").asText()).isEqualTo(APP_REF);
    }

    @Test
    void packagesOutsideTheInstallDirStayOsComponents() throws IOException {
        JsonNode described = describeArm64();

        assertThat(described.path("components").findValuesAsText("purl")).contains(NPM);
    }

    @Test
    void theSamePackageInstalledElsewhereByTheBaseImageIsKeptAsItsOwnComponent() throws IOException {
        ObjectNode scan = scan(LZ4_ARM64);
        String copy = scanned(scan, EXPRESS, "/usr/local/lib/node_modules/npm/node_modules/express/package.json");

        JsonNode described = SbomImage.describe(scan, image("arm64"), List.of(app(appSbom())));

        assertThat(SbomChecks.componentRefs(described)).contains(EXPRESS, copy);
        assertThat(Boms.reachable(described, IMAGE_REF)).containsAll(SbomChecks.componentRefs(described));
    }

    @Test
    void failsWhenTheImageHasAPackageTheSbomDoesNotList() {
        ObjectNode scan = scan(LZ4_ARM64);
        scanned(scan, "pkg:npm/left-pad@1.3.0", APP_DIR + "/node_modules/left-pad/package.json");

        assertThatThrownBy(() -> SbomImage.describe(scan, image("arm64"), List.of(app(appSbom()))))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("The image has pkg:npm/left-pad@1.3.0 at " + APP_DIR + "/node_modules/left-pad/package.json, which the SBOM of " + APP_REF + " does not list");
    }

    @Test
    void failsWhenTheImageHasAnotherVersionWhereTheSbomListsAPackage() {
        ObjectNode scan = scan(LZ4_ARM64);
        SbomImageTest.removeComponent(scan, EXPRESS + "?package-id=" + Integer.toHexString((APP_DIR + "/node_modules/express/package.json").hashCode()));
        scanned(scan, "pkg:npm/express@5.2.0", APP_DIR + "/node_modules/express/package.json");

        assertThatThrownBy(() -> SbomImage.describe(scan, image("arm64"), List.of(app(appSbom()))))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("The image has pkg:npm/express@5.2.0 at " + APP_DIR + "/node_modules/express/package.json, but the SBOM of " + APP_REF + " lists " + EXPRESS + " there");
    }

    @Test
    void failsWhenARequiredPackageIsNotInstalled() {
        ObjectNode scan = scan(LZ4_ARM64);
        SbomImageTest.removeComponent(scan, EXPRESS + "?package-id=" + Integer.toHexString((APP_DIR + "/node_modules/express/package.json").hashCode()));

        assertThatThrownBy(() -> SbomImage.describe(scan, image("arm64"), List.of(app(appSbom()))))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("The SBOM of " + APP_REF + " lists " + EXPRESS + " at [" + APP_DIR + "/node_modules/express], but the image does not have it there");
    }

    @Test
    void failsWhenAPlatformPackageIsInstalledThatTheSbomDoesNotList() throws IOException {
        ObjectNode scan = scan(LZ4_ARM64, "pkg:npm/%40antoniomuso/lz4-napi-linux-arm64-musl@2.10.0");

        assertThatThrownBy(() -> SbomImage.describe(scan, image("arm64"), List.of(app(appSbom()))))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("lz4-napi-linux-arm64-musl@2.10.0")
                .hasMessageContaining("does not list");
    }

    @Test
    void failsWhenARequiredPackageHasNoPath() {
        ObjectNode sbom = appSbom();
        Boms.component(sbom, "pkg:npm/orphan@1.0.0", "pkg:npm/orphan@1.0.0");
        ((ArrayNode) sbom.path("dependencies").get(0).path("dependsOn")).add("pkg:npm/orphan@1.0.0");

        assertThatThrownBy(() -> SbomImage.describe(scan(LZ4_ARM64), image("arm64"), List.of(app(sbom))))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("lists pkg:npm/orphan@1.0.0 without the path it is installed at");
    }

    @Test
    void aBundleClaimsWhatTheScanFoundInsideIt() throws IOException {
        ObjectNode scan = scan(LZ4_ARM64);
        scanned(scan, HUGERTE, APP_DIR + "/web/public/assets/hugerte/package.json");

        JsonNode described = SbomImage.describe(scan, image("arm64"), List.of(app(appSbom()), ui(uiSbom(), APP_DIR + "/web")));

        assertThat(SbomChecks.componentRefs(described)).contains(UI_REF, HUGERTE, ANGULAR).noneMatch(ref -> ref.startsWith(HUGERTE + "?"));
        assertThat(Boms.graph(described).get(IMAGE_REF)).contains(APP_REF, UI_REF);
        assertThat(Boms.reachable(described, IMAGE_REF)).containsAll(SbomChecks.componentRefs(described));
        assertThat(new JsonParser().validate(described, Version.VERSION_16)).isEmpty();
    }

    @Test
    void failsWhenABundleHasAPackageItsSbomDoesNotList() {
        ObjectNode scan = scan(LZ4_ARM64);
        scanned(scan, "pkg:npm/tinymce@7.0.0", APP_DIR + "/web/public/assets/tinymce/package.json");

        assertThatThrownBy(() -> SbomImage.describe(scan, image("arm64"), List.of(app(appSbom()), ui(uiSbom(), APP_DIR + "/web"))))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("The image has pkg:npm/tinymce@7.0.0 at " + APP_DIR + "/web/public/assets/tinymce/package.json, which the SBOM of " + UI_REF + " does not list");
    }

    @Test
    void resultIsValidAgainstTheCycloneDxSchema() throws IOException {
        assertThat(new JsonParser().validate(describeArm64(), Version.VERSION_16)).isEmpty();
    }

    @Test
    void failsWhenAnSbomComponentHasNothingToCheckItAgainst() {
        BundledComponent component = new BundledComponent("library", null, null, null).sbom(tempDir.resolve("x.cdx.json").toFile());

        assertThatThrownBy(() -> SbomImage.describe(scan(), image("arm64"), List.of(component)))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("must set exactly one of file, installDir and bundleDir to check its SBOM against, but sets []");
    }

    @Test
    void failsWhenAnSbomComponentSetsTwoAnchors() {
        BundledComponent component = new BundledComponent("library", null, null, tempDir.toFile()).sbom(tempDir.resolve("x.cdx.json").toFile()).installDir(APP_DIR);

        assertThatThrownBy(() -> SbomImage.describe(scan(), image("arm64"), List.of(component)))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("but sets [file, installDir]");
    }

    @Test
    void failsOnARelativeInstallDir() {
        BundledComponent component = new BundledComponent("library", null, null, null).sbom(tempDir.resolve("x.cdx.json").toFile()).installDir("usr/share/app/");

        assertThatThrownBy(() -> SbomImage.describe(scan(), image("arm64"), List.of(component)))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("must be an absolute path in the image without a trailing slash");
    }

    @Test
    void failsWhenADirectoryIsSetWithoutSbom() {
        BundledComponent component = new BundledComponent("application", "chrome", "1.0", null).installDir(APP_DIR);

        assertThatThrownBy(() -> SbomImage.describe(scan(), image("arm64"), List.of(component)))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("sets installDir or bundleDir, which need an SBOM to check the image against");
    }

    @Test
    void failsOnAnUnresolvedProperty() {
        BundledComponent component = new BundledComponent("application", "chrome-for-testing", "${chromium.version}", null);

        assertThatThrownBy(() -> SbomImage.describe(scan(), image("arm64"), List.of(component)))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("has the unresolved property in ${chromium.version}");
    }

}
