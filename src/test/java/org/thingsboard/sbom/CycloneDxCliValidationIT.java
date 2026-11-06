// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
package org.thingsboard.sbom;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.startupcheck.OneShotStartupCheckStrategy;
import org.testcontainers.images.builder.Transferable;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@Testcontainers(disabledWithoutDocker = true)
class CycloneDxCliValidationIT {

    private static final DockerImageName CLI_IMAGE = DockerImageName.parse("cyclonedx/cyclonedx-cli:0.33.1");

    @Test
    void mergedFixturesPassTheOfficialCliValidation() {
        ObjectNode merged = SbomMerger.merge(Boms.mavenFixture(), Boms.npmFixture(), Boms.HOST_PREFIX);

        CliResult result = validate(merged);

        assertThat(result.passed()).as(result.logs()).isTrue();
        assertThat(result.logs()).contains("BOM validated successfully");
    }

    @Test
    void mergedFixturesWithMetadataPassTheOfficialCliValidation() {
        ObjectNode merged = SbomMerger.merge(Boms.mavenFixture(), Boms.npmFixture(), Boms.HOST_PREFIX);
        ObjectNode updated = SbomMetadata.apply(merged, SbomMetadataTest.THINGSBOARD, SbomMetadataTest.THINGSBOARD, SbomMetadataTest.THINGSBOARD);

        CliResult result = validate(updated);

        assertThat(result.passed()).as(result.logs()).isTrue();
    }

    @Test
    void mergedSyntheticBomsPassTheOfficialCliValidation() {
        ObjectNode merged = SbomMerger.merge(Boms.simpleTarget(), Boms.simpleNested(), Boms.HOST_PREFIX);

        CliResult result = validate(merged);

        assertThat(result.passed()).as(result.logs()).isTrue();
    }

    @Test
    void fixturesThemselvesPassTheOfficialCliValidation() {
        assertThat(validate(Boms.mavenFixture()).passed()).isTrue();
        assertThat(validate(Boms.npmFixture()).passed()).isTrue();
    }

    @Test
    void packageSbomPassesTheOfficialCliValidation(@TempDir Path tempDir) throws IOException {
        Path deb = Files.writeString(tempDir.resolve("thingsboard.deb"), "deb contents");
        Path bundle = Files.writeString(tempDir.resolve("extension.js"), "console.log('extension');");
        Path registry = Files.createDirectory(tempDir.resolve("registry"));
        Files.writeString(registry.resolve("3.xml"), "<LWM2M/>");
        Path certificate = tempDir.resolve("root-ca.crt.pem");
        try (InputStream in = CycloneDxCliValidationIT.class.getResourceAsStream("/fixtures/root-ca.crt.pem")) {
            Files.copy(in, certificate);
        }
        List<BundledComponent> components = List.of(
                new BundledComponent("library", "gateway-management-extension", "4.4.0.1", bundle.toFile())
                        .supplier(SbomMetadataTest.THINGSBOARD).license("Apache-2.0"),
                new BundledComponent("data", "lwm2m-registry", null, registry.toFile()),
                new BundledComponent("cryptographic-asset", "DigiCert Global Root G2", null, certificate.toFile()));

        ObjectNode described = SbomPackage.describe(SbomPackageTest.application(), "thingsboard", "4.4.0.1",
                new PackageFile("deb", deb.toFile(), SbomPackageTest.DEB_PURL, false), components);

        CliResult result = validate(described);

        assertThat(result.passed()).as(result.logs()).isTrue();
    }

    @Test
    void imageSbomPassesTheOfficialCliValidation(@TempDir Path tempDir) throws IOException {
        Path deb = Files.writeString(tempDir.resolve("tb-mqtt-transport.deb"), "deb contents");
        Path applicationSbom = Files.writeString(tempDir.resolve("application.cdx.json"), SbomPackageTest.application().toPrettyString());
        Path packageSbom = SbomPackage.writeAll(applicationSbom, "tb-mqtt-transport", "4.4.1", List.of(new PackageFile("deb", deb.toFile(), SbomImageTest.DEB_PURL, false)), List.of()).get(0);

        ObjectNode described = SbomImage.describe(SbomImageTest.osSbom(), SbomImageTest.image(),
                List.of(new BundledComponent("library", null, null, deb.toFile()).sbom(packageSbom.toFile())));

        CliResult result = validate(described);

        assertThat(result.passed()).as(result.logs()).isTrue();
    }

    @Test
    void cliRejectsAnInvalidBom() {
        ObjectNode broken = SbomMerger.merge(Boms.mavenFixture(), Boms.npmFixture(), Boms.HOST_PREFIX);
        ((ObjectNode) broken.get("components").get(0)).remove("name");

        CliResult result = validate(broken);

        assertThat(result.passed()).as(result.logs()).isFalse();
    }

    private static CliResult validate(JsonNode bom) {
        try (GenericContainer<?> cli = new GenericContainer<>(CLI_IMAGE)
                .withCopyToContainer(Transferable.of(bom.toPrettyString().getBytes(StandardCharsets.UTF_8)), "/bom.json")
                .withCommand("validate", "--input-file", "/bom.json", "--input-format", "json",
                        "--input-version", "v" + bom.path("specVersion").asText().replace('.', '_'), "--fail-on-errors")
                .withStartupCheckStrategy(new OneShotStartupCheckStrategy().withTimeout(Duration.ofMinutes(2)))) {
            try {
                cli.start();
                return new CliResult(true, cli.getLogs());
            } catch (RuntimeException e) {
                return new CliResult(false, logsOrError(cli, e));
            }
        }
    }

    private static String logsOrError(GenericContainer<?> cli, RuntimeException startError) {
        try {
            return cli.getLogs();
        } catch (RuntimeException e) {
            return String.valueOf(startError.getMessage());
        }
    }

    private record CliResult(boolean passed, String logs) {
    }

}
