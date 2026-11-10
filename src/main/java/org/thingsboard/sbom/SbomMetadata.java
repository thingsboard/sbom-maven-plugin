// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
package org.thingsboard.sbom;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.math.BigDecimal;
import java.nio.file.Path;
import java.time.DateTimeException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;

import static org.thingsboard.sbom.SbomChecks.check;
import static org.thingsboard.sbom.SbomJson.putIfPresent;

public final class SbomMetadata {

    private static final BigDecimal MIN_SPEC_VERSION = new BigDecimal("1.6");
    /**
     * What newer Maven versions set {@code project.build.outputTimestamp} to when the project does not: not a time anything was made.
     */
    private static final Instant MAVEN_PLACEHOLDER = Instant.parse("1980-02-01T00:00:00Z");

    private SbomMetadata() {}

    public static List<String> applyToFile(Path targetFile, Organization manufacturer, Organization supplier, Organization componentManufacturer, String outputTimestamp) {
        String timestamp = timestamp(outputTimestamp);
        JsonNode target = SbomFiles.readFile(targetFile);
        SbomFiles.writeFile(targetFile, apply(target, manufacturer, supplier, componentManufacturer, timestamp));
        return describe(manufacturer, supplier, componentManufacturer, timestamp);
    }

    public static ObjectNode apply(JsonNode target, Organization manufacturer, Organization supplier, Organization componentManufacturer) {
        return apply(target, manufacturer, supplier, componentManufacturer, null);
    }

    /**
     * {@code timestamp} is what {@link #timestamp} returns: null leaves the timestamp of the SBOM as it is.
     */
    public static ObjectNode apply(JsonNode target, Organization manufacturer, Organization supplier, Organization componentManufacturer, String timestamp) {
        check(manufacturer != null || supplier != null || componentManufacturer != null || timestamp != null,
                "No metadata configured: set at least one of manufacturer, supplier, componentManufacturer, timestamp");
        SbomChecks.checkInput("Target", target);
        String specVersion = target.path("specVersion").asText();
        check(new BigDecimal(specVersion).compareTo(MIN_SPEC_VERSION) >= 0,
                "Target SBOM is CycloneDX " + specVersion + "; manufacturer fields need CycloneDX " + MIN_SPEC_VERSION + " or later");

        ObjectNode updated = (ObjectNode) target.deepCopy();
        ObjectNode metadata = updated.withObjectProperty("metadata");
        if (timestamp != null) {
            metadata.put("timestamp", timestamp);
        }
        if (manufacturer != null) {
            metadata.set("manufacturer", toJson("manufacturer", manufacturer));
        }
        if (supplier != null) {
            metadata.set("supplier", toJson("supplier", supplier));
        }
        if (componentManufacturer != null) {
            metadata.withObjectProperty("component").set("manufacturer", toJson("componentManufacturer", componentManufacturer));
        }

        SbomChecks.checkInput("Updated", updated);
        check(withoutManagedFields(updated).equals(withoutManagedFields(target)), "Updated SBOM changed more than the configured metadata");
        return updated;
    }

    /**
     * The value of Maven's {@code project.build.outputTimestamp} as a CycloneDX timestamp, in UTC to the second.
     * Null when it is not set, is the placeholder Maven sets by itself or, as Maven reads it, a single character switches it off.
     */
    static String timestamp(String outputTimestamp) {
        if (outputTimestamp == null || outputTimestamp.strip().length() < 2) {
            return null;
        }
        String value = outputTimestamp.strip();
        try {
            Instant instant = value.chars().allMatch(Character::isDigit)
                    ? Instant.ofEpochSecond(Long.parseLong(value))
                    : OffsetDateTime.parse(value).toInstant();
            return instant.equals(MAVEN_PLACEHOLDER) ? null : instant.truncatedTo(ChronoUnit.SECONDS).toString();
        } catch (DateTimeException | NumberFormatException e) {
            throw new SbomException("Timestamp " + value + " must be a date and time with an offset, for example 2026-01-31T12:00:00Z, or seconds since 1970", e);
        }
    }

    static ObjectNode toJson(String label, Organization organization) {
        check(organization.getName() != null && !organization.getName().isBlank(), label + " has no name");
        ObjectNode json = JsonNodeFactory.instance.objectNode().put("name", organization.getName());
        if (!organization.getUrls().isEmpty()) {
            ArrayNode urls = json.putArray("url");
            for (String url : organization.getUrls()) {
                check(url != null && !url.isBlank(), label + " has a blank url");
                urls.add(url);
            }
        }
        if (!organization.getContacts().isEmpty()) {
            ArrayNode contacts = json.putArray("contact");
            for (Contact contact : organization.getContacts()) {
                ObjectNode contactJson = contacts.addObject();
                putIfPresent(contactJson, "name", contact.getName());
                putIfPresent(contactJson, "email", contact.getEmail());
                putIfPresent(contactJson, "phone", contact.getPhone());
                check(!contactJson.isEmpty(), label + " has a contact without name, email or phone");
            }
        }
        return json;
    }

    private static JsonNode withoutManagedFields(JsonNode bom) {
        ObjectNode copy = (ObjectNode) bom.deepCopy();
        JsonNode metadata = copy.path("metadata");
        if (metadata instanceof ObjectNode metadataObject) {
            metadataObject.remove(List.of("timestamp", "manufacturer", "supplier"));
            if (metadataObject.path("component") instanceof ObjectNode component) {
                component.remove("manufacturer");
            }
        }
        return copy;
    }

    private static List<String> describe(Organization manufacturer, Organization supplier, Organization componentManufacturer, String timestamp) {
        List<String> fields = new ArrayList<>();
        if (timestamp != null) {
            fields.add("metadata.timestamp");
        }
        if (manufacturer != null) {
            fields.add("metadata.manufacturer");
        }
        if (supplier != null) {
            fields.add("metadata.supplier");
        }
        if (componentManufacturer != null) {
            fields.add("metadata.component.manufacturer");
        }
        return fields;
    }

}
