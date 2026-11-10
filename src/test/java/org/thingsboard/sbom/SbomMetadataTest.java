// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
package org.thingsboard.sbom;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.cyclonedx.Version;
import org.cyclonedx.parsers.JsonParser;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SbomMetadataTest {

    static final Organization THINGSBOARD = new Organization("ThingsBoard, Inc.", List.of("https://thingsboard.io"),
            List.of(new Contact(null, "security@thingsboard.io", null)));
    static final Organization RESELLER = new Organization("Reseller Ltd", List.of(), List.of());
    static final String TIMESTAMP = "2026-01-31T12:00:00Z";

    @TempDir
    Path tempDir;

    @Test
    void setsManufacturerSupplierAndComponentManufacturer() throws IOException {
        JsonNode updated = SbomMetadata.apply(Boms.mavenFixture(), THINGSBOARD, RESELLER, THINGSBOARD);

        JsonNode expectedThingsBoard = Boms.MAPPER.readTree("""
                {"name":"ThingsBoard, Inc.","url":["https://thingsboard.io"],"contact":[{"email":"security@thingsboard.io"}]}""");
        assertThat(updated.path("metadata").path("manufacturer")).isEqualTo(expectedThingsBoard);
        assertThat(updated.path("metadata").path("supplier")).isEqualTo(Boms.MAPPER.readTree("{\"name\":\"Reseller Ltd\"}"));
        assertThat(updated.path("metadata").path("component").path("manufacturer")).isEqualTo(expectedThingsBoard);
    }

    @Test
    void leavesEverythingElseUnchanged() {
        ObjectNode target = Boms.mavenFixture();

        ObjectNode updated = SbomMetadata.apply(target, THINGSBOARD, THINGSBOARD, THINGSBOARD);

        ((ObjectNode) updated.get("metadata")).remove(List.of("manufacturer", "supplier"));
        ((ObjectNode) updated.get("metadata").get("component")).remove("manufacturer");
        assertThat(updated).isEqualTo(target);
    }

    @Test
    void setsTheTimestampAndReplacesTheOneOfTheSbom() {
        ObjectNode target = Boms.mavenFixture();
        ((ObjectNode) target.get("metadata")).put("timestamp", "2020-01-01T00:00:00Z");

        ObjectNode updated = SbomMetadata.apply(target, null, null, null, TIMESTAMP);

        assertThat(updated.path("metadata").path("timestamp").asText()).isEqualTo(TIMESTAMP);
        ((ObjectNode) updated.get("metadata")).put("timestamp", "2020-01-01T00:00:00Z");
        assertThat(updated).isEqualTo(target);
    }

    @Test
    void withoutATimestampTheOneOfTheSbomStays() {
        ObjectNode target = Boms.mavenFixture();
        ((ObjectNode) target.get("metadata")).put("timestamp", "2020-01-01T00:00:00Z");

        JsonNode updated = SbomMetadata.apply(target, THINGSBOARD, null, null, null);

        assertThat(updated.path("metadata").path("timestamp").asText()).isEqualTo("2020-01-01T00:00:00Z");
    }

    @Test
    void theTimestampIsReadAsMavenReadsItsOutputTimestamp() {
        assertThat(SbomMetadata.timestamp("2026-01-31T12:00:00Z")).isEqualTo(TIMESTAMP);
        assertThat(SbomMetadata.timestamp(" 2026-01-31T14:00:00+02:00 ")).isEqualTo(TIMESTAMP);
        assertThat(SbomMetadata.timestamp("2026-01-31T12:00:00.123Z")).isEqualTo(TIMESTAMP);
        assertThat(SbomMetadata.timestamp("1769860800")).isEqualTo(TIMESTAMP);
        // Not set, or switched off with a single character
        assertThat(SbomMetadata.timestamp(null)).isNull();
        assertThat(SbomMetadata.timestamp("")).isNull();
        assertThat(SbomMetadata.timestamp("x")).isNull();
        // What Maven 3.10 sets when the project does not
        assertThat(SbomMetadata.timestamp("1980-02-01T00:00:00Z")).isNull();
    }

    @Test
    void failsOnATimestampThatIsNotADateAndTimeWithAnOffset() {
        for (String timestamp : List.of("2026-01-31", "2026-01-31T12:00:00", "yesterday", "${project.build.outputTimestamp}")) {
            assertThatThrownBy(() -> SbomMetadata.timestamp(timestamp))
                    .isInstanceOf(SbomException.class)
                    .hasMessageContaining("Timestamp " + timestamp + " must be a date and time with an offset");
        }
    }

    @Test
    void onlyTheConfiguredFieldsAreSet() {
        JsonNode updated = SbomMetadata.apply(Boms.mavenFixture(), null, THINGSBOARD, null);

        assertThat(updated.path("metadata").has("supplier")).isTrue();
        assertThat(updated.path("metadata").has("manufacturer")).isFalse();
        assertThat(updated.path("metadata").path("component").has("manufacturer")).isFalse();
    }

    @Test
    void fieldsThatAreNotConfiguredKeepTheirExistingValues() {
        JsonNode first = SbomMetadata.apply(Boms.mavenFixture(), THINGSBOARD, null, null);

        JsonNode second = SbomMetadata.apply(first, null, RESELLER, null);

        assertThat(second.path("metadata").path("manufacturer").path("name").asText()).isEqualTo("ThingsBoard, Inc.");
        assertThat(second.path("metadata").path("supplier").path("name").asText()).isEqualTo("Reseller Ltd");
    }

    @Test
    void configuredValuesReplaceExistingOnes() {
        JsonNode first = SbomMetadata.apply(Boms.mavenFixture(), RESELLER, RESELLER, RESELLER);

        JsonNode second = SbomMetadata.apply(first, THINGSBOARD, THINGSBOARD, THINGSBOARD);

        assertThat(second).isEqualTo(SbomMetadata.apply(Boms.mavenFixture(), THINGSBOARD, THINGSBOARD, THINGSBOARD));
    }

    @Test
    void applyingTwiceGivesTheSameResult() {
        ObjectNode once = SbomMetadata.apply(Boms.mavenFixture(), THINGSBOARD, THINGSBOARD, THINGSBOARD);

        assertThat(SbomMetadata.apply(once, THINGSBOARD, THINGSBOARD, THINGSBOARD)).isEqualTo(once);
    }

    @Test
    void inputIsNotModified() {
        ObjectNode target = Boms.mavenFixture();

        SbomMetadata.apply(target, THINGSBOARD, THINGSBOARD, THINGSBOARD);

        assertThat(target).isEqualTo(Boms.mavenFixture());
    }

    @Test
    void resultIsValidAgainstTheCycloneDxSchema() throws IOException {
        ObjectNode updated = SbomMetadata.apply(Boms.mavenFixture(), THINGSBOARD, THINGSBOARD, THINGSBOARD);

        assertThat(new JsonParser().validate(updated, Version.VERSION_16)).isEmpty();
    }

    @Test
    void worksTogetherWithMergeInEitherOrder() {
        ObjectNode metadataThenMerge = SbomMerger.merge(SbomMetadata.apply(Boms.mavenFixture(), THINGSBOARD, THINGSBOARD, THINGSBOARD),
                Boms.npmFixture(), Boms.HOST_PREFIX);
        ObjectNode mergeThenMetadata = SbomMetadata.apply(SbomMerger.merge(Boms.mavenFixture(), Boms.npmFixture(), Boms.HOST_PREFIX),
                THINGSBOARD, THINGSBOARD, THINGSBOARD);

        assertThat(metadataThenMerge).isEqualTo(mergeThenMetadata);
    }

    @Test
    void failsWhenNothingIsConfigured() {
        assertThatThrownBy(() -> SbomMetadata.apply(Boms.mavenFixture(), null, null, null))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("No metadata configured");
    }

    @Test
    void failsWhenTheOrganizationHasNoName() {
        Organization unnamed = new Organization(" ", List.of(), List.of());

        assertThatThrownBy(() -> SbomMetadata.apply(Boms.mavenFixture(), unnamed, null, null))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("manufacturer has no name");
    }

    @Test
    void failsOnABlankUrl() {
        Organization blankUrl = new Organization("ThingsBoard, Inc.", List.of(""), List.of());

        assertThatThrownBy(() -> SbomMetadata.apply(Boms.mavenFixture(), null, blankUrl, null))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("supplier has a blank url");
    }

    @Test
    void failsOnAnEmptyContact() {
        Organization emptyContact = new Organization("ThingsBoard, Inc.", List.of(), List.of(new Contact(" ", null, "")));

        assertThatThrownBy(() -> SbomMetadata.apply(Boms.mavenFixture(), null, null, emptyContact))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("componentManufacturer has a contact without name, email or phone");
    }

    @Test
    void failsOnASpecVersionWithoutManufacturerFields() {
        ObjectNode legacy = Boms.bom("1.5", "app");

        assertThatThrownBy(() -> SbomMetadata.apply(legacy, THINGSBOARD, null, null))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("Target SBOM is CycloneDX 1.5; manufacturer fields need CycloneDX 1.6 or later");
    }

    @Test
    void failsOnAnInvalidTarget() {
        ObjectNode target = Boms.mavenFixture();
        target.put("bomFormat", "SPDX");

        assertThatThrownBy(() -> SbomMetadata.apply(target, THINGSBOARD, null, null))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("Target SBOM is not a CycloneDX document");
    }

    @Test
    void writesTheTargetFileInPlace() throws IOException {
        Path file = Files.writeString(tempDir.resolve("application.cdx.json"), Boms.mavenFixture().toPrettyString());

        List<String> fields = SbomMetadata.applyToFile(file, THINGSBOARD, THINGSBOARD, null, "2026-01-31T14:00:00+02:00");

        assertThat(fields).containsExactly("metadata.timestamp", "metadata.manufacturer", "metadata.supplier");
        assertThat(Boms.MAPPER.readTree(file.toFile())).isEqualTo(SbomMetadata.apply(Boms.mavenFixture(), THINGSBOARD, THINGSBOARD, null, TIMESTAMP));
    }

    @Test
    void leavesTheTargetFileUntouchedWhenItFails() throws IOException {
        String original = Boms.mavenFixture().toPrettyString();
        Path file = Files.writeString(tempDir.resolve("application.cdx.json"), original);

        assertThatThrownBy(() -> SbomMetadata.applyToFile(file, new Organization("", List.of(), List.of()), null, null, null))
                .isInstanceOf(SbomException.class);

        assertThat(Files.readString(file)).isEqualTo(original);
    }

}
