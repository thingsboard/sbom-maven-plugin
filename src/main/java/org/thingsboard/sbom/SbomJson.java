// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
package org.thingsboard.sbom;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.thingsboard.sbom.SbomChecks.check;

final class SbomJson {

    private SbomJson() {
    }

    static ObjectNode newBom(String specVersion, String serialSeed) {
        ObjectNode bom = JsonNodeFactory.instance.objectNode();
        bom.put("bomFormat", "CycloneDX");
        bom.put("specVersion", specVersion);
        bom.put("serialNumber", "urn:uuid:" + UUID.nameUUIDFromBytes(serialSeed.getBytes(StandardCharsets.UTF_8)));
        bom.put("version", 1);
        return bom;
    }

    static void putDependencies(ObjectNode bom, Map<String, Set<String>> graph) {
        ArrayNode dependencies = bom.putArray("dependencies");
        graph.forEach((ref, targets) -> {
            ObjectNode entry = dependencies.addObject().put("ref", ref);
            if (!targets.isEmpty()) {
                ArrayNode dependsOn = entry.putArray("dependsOn");
                targets.forEach(dependsOn::add);
            }
        });
    }

    static void addComponent(ArrayNode bomComponents, Map<String, JsonNode> componentsByRef, JsonNode component, String source) {
        String ref = component.path("bom-ref").asText();
        JsonNode known = componentsByRef.get(ref);
        if (known == null) {
            bomComponents.add(component.deepCopy());
            componentsByRef.put(ref, component);
            return;
        }
        check(!component.path("purl").asText().isEmpty() && known.path("purl").asText().equals(component.path("purl").asText()),
                "Component " + ref + " from " + source + " clashes with a different component that is already in the SBOM");
    }

    static void copyFields(JsonNode from, ObjectNode to, String... fields) {
        for (String field : fields) {
            if (from.has(field)) {
                to.set(field, from.get(field).deepCopy());
            }
        }
    }

    static void putIfPresent(ObjectNode json, String field, String value) {
        if (value != null && !value.isBlank()) {
            json.put(field, value);
        }
    }

    static ArrayNode hashesJson(Map<String, String> hashes) {
        ArrayNode json = JsonNodeFactory.instance.arrayNode();
        hashes.forEach((alg, content) -> json.addObject().put("alg", alg).put("content", content));
        return json;
    }

}
