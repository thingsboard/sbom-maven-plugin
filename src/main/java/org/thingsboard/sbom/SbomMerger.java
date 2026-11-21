// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
package org.thingsboard.sbom;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;

public final class SbomMerger {

    private SbomMerger() {}

    public static ObjectNode merge(JsonNode target, JsonNode nested, String hostPurlPrefix) {
        return mergeIntoHost(target, nested, () -> SbomChecks.findHostRef(target, hostPurlPrefix));
    }

    public static ObjectNode mergeIntoRoot(JsonNode target, JsonNode nested) {
        return mergeIntoHost(target, nested, () -> SbomChecks.rootRef(target));
    }

    private static ObjectNode mergeIntoHost(JsonNode target, JsonNode nested, Supplier<String> hostRefSupplier) {
        SbomChecks.checkInput("Target", target);
        SbomChecks.checkInput("Nested", nested);
        SbomChecks.checkSameSpecVersion(target, nested);
        String hostRef = hostRefSupplier.get();
        String nestedRootRef = SbomChecks.checkNestedRoot(nested);
        String targetRootRef = SbomChecks.rootRef(target);
        SbomChecks.check(!SbomChecks.componentRefs(nested).contains(targetRootRef),
                "Nested component " + targetRootRef + " conflicts with the target root component");

        ObjectNode merged = (ObjectNode) target.deepCopy();
        mergeComponents(merged, nested);
        mergeDependencies(merged, nested, nestedRootRef, hostRef);
        mergeTools(merged, nested);

        SbomChecks.checkOutput(target, nested, merged, hostRef, nestedRootRef);
        return merged;
    }

    private static void mergeComponents(ObjectNode merged, JsonNode nested) {
        ArrayNode components = merged.withArrayProperty("components");
        Map<String, JsonNode> componentsByRef = new HashMap<>();
        components.forEach(component -> componentsByRef.put(component.path("bom-ref").asText(), component));
        for (JsonNode component : nested.path("components")) {
            String ref = component.path("bom-ref").asText();
            JsonNode existing = componentsByRef.get(ref);
            if (existing == null) {
                components.add(component.deepCopy());
            } else if (!existing.equals(component)) {
                throw new SbomException("Nested component " + ref + " conflicts with a different target component with the same bom-ref");
            }
        }
    }

    private static void mergeDependencies(ObjectNode merged, JsonNode nested, String nestedRootRef, String hostRef) {
        ArrayNode dependencies = merged.withArrayProperty("dependencies");
        Map<String, ObjectNode> dependenciesByRef = new HashMap<>();
        dependencies.forEach(dependency -> dependenciesByRef.put(dependency.path("ref").asText(), (ObjectNode) dependency));
        for (JsonNode dependency : nested.path("dependencies")) {
            String ref = remap(dependency.path("ref").asText(), nestedRootRef, hostRef);
            ObjectNode entry = dependenciesByRef.computeIfAbsent(ref, newRef -> dependencies.addObject().put("ref", newRef));
            if (dependency.path("dependsOn").isEmpty()) {
                continue;
            }
            ArrayNode dependsOn = entry.withArrayProperty("dependsOn");
            Set<String> known = new HashSet<>();
            dependsOn.forEach(target -> known.add(target.asText()));
            for (JsonNode target : dependency.path("dependsOn")) {
                String targetRef = remap(target.asText(), nestedRootRef, hostRef);
                if (known.add(targetRef)) {
                    dependsOn.add(targetRef);
                }
            }
        }
    }

    private static String remap(String ref, String nestedRootRef, String hostRef) {
        return ref.equals(nestedRootRef) ? hostRef : ref;
    }

    static void mergeTools(ObjectNode merged, JsonNode nested) {
        ArrayNode tools = merged.withObjectProperty("metadata").withObjectProperty("tools").withArrayProperty("components");
        Set<String> known = new HashSet<>();
        tools.forEach(tool -> known.add(toolKey(tool)));
        for (JsonNode tool : nested.path("metadata").path("tools").path("components")) {
            if (known.add(toolKey(tool))) {
                tools.add(tool.deepCopy());
            }
        }
    }

    private static String toolKey(JsonNode tool) {
        return tool.path("group").asText() + ":" + tool.path("name").asText() + ":" + tool.path("version").asText();
    }

}
