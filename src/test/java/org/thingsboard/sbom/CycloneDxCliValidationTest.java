package org.thingsboard.sbom;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.startupcheck.OneShotStartupCheckStrategy;
import org.testcontainers.images.builder.Transferable;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.nio.charset.StandardCharsets;
import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

@Testcontainers(disabledWithoutDocker = true)
class CycloneDxCliValidationTest {

    private static final DockerImageName CLI_IMAGE = DockerImageName.parse("cyclonedx/cyclonedx-cli:0.33.1");

    @Test
    void mergedFixturesPassTheOfficialCliValidation() {
        ObjectNode merged = SbomMerger.merge(Boms.mavenFixture(), Boms.npmFixture(), Boms.HOST_PREFIX);

        CliResult result = validate(merged);

        assertThat(result.passed()).as(result.logs()).isTrue();
        assertThat(result.logs()).contains("BOM validated successfully");
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
