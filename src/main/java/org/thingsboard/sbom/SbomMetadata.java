package org.thingsboard.sbom;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.math.BigDecimal;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.thingsboard.sbom.SbomChecks.check;
import static org.thingsboard.sbom.SbomJson.putIfPresent;

public final class SbomMetadata {

    private static final BigDecimal MIN_SPEC_VERSION = new BigDecimal("1.6");

    private SbomMetadata() {
    }

    public static List<String> applyToFile(Path targetFile, Organization manufacturer, Organization supplier, Organization componentManufacturer) {
        JsonNode target = SbomFiles.readFile(targetFile);
        SbomFiles.writeFile(targetFile, apply(target, manufacturer, supplier, componentManufacturer));
        return describe(manufacturer, supplier, componentManufacturer);
    }

    public static ObjectNode apply(JsonNode target, Organization manufacturer, Organization supplier, Organization componentManufacturer) {
        check(manufacturer != null || supplier != null || componentManufacturer != null,
                "No metadata configured: set at least one of manufacturer, supplier, componentManufacturer");
        SbomChecks.checkInput("Target", target);
        String specVersion = target.path("specVersion").asText();
        check(new BigDecimal(specVersion).compareTo(MIN_SPEC_VERSION) >= 0,
                "Target SBOM is CycloneDX " + specVersion + "; manufacturer fields need CycloneDX " + MIN_SPEC_VERSION + " or later");

        ObjectNode updated = (ObjectNode) target.deepCopy();
        ObjectNode metadata = updated.withObjectProperty("metadata");
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
            metadataObject.remove(List.of("manufacturer", "supplier"));
            if (metadataObject.path("component") instanceof ObjectNode component) {
                component.remove("manufacturer");
            }
        }
        return copy;
    }

    private static List<String> describe(Organization manufacturer, Organization supplier, Organization componentManufacturer) {
        List<String> fields = new ArrayList<>();
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
