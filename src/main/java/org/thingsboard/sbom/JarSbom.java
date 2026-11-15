// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
package org.thingsboard.sbom;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.cyclonedx.generators.BomGeneratorFactory;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.LifecycleChoice;
import org.cyclonedx.model.Lifecycles;
import org.cyclonedx.model.Metadata;
import org.cyclonedx.model.Property;
import org.cyclonedx.model.metadata.ToolInformation;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The SBOM of a jar: one component per library that the jar packs, and the dependency graph between them.
 */
final class JarSbom {
    private JarSbom() {}

    /**
     * @param root         the component of the project
     * @param tool         the component of the tool that makes the SBOM
     * @param components   one component per packed library
     * @param graph        what each artifact of the project depends on, by bom-ref; it may name artifacts that are not packed
     * @param reproducible whether the build has a fixed time, so the SBOM is the same each time it is made
     */
    static ObjectNode bom(Component root, Component tool, List<Component> components, Map<String, Set<String>> graph, boolean reproducible) {
        Metadata metadata = new Metadata();
        metadata.setComponent(root);
        ToolInformation tools = new ToolInformation();
        tools.setComponents(List.of(tool));
        metadata.setToolChoice(tools);
        metadata.addProperty(property("maven.goal", "jar"));
        if (reproducible) {
            metadata.addProperty(property("cdx:reproducible", "enabled"));
        }
        LifecycleChoice build = new LifecycleChoice();
        build.setPhase(LifecycleChoice.Phase.BUILD);
        Lifecycles lifecycles = new Lifecycles();
        lifecycles.setLifecycleChoice(List.of(build));
        metadata.setLifecycles(lifecycles);

        Bom bom = new Bom();
        bom.setMetadata(metadata);
        bom.setComponents(components);
        StringBuilder serialSeed = new StringBuilder(root.getGroup() + ":" + root.getName() + ":" + root.getVersion());
        metadata.getProperties().forEach(property -> serialSeed.append(';').append(property.getName()).append('=').append(property.getValue()));
        bom.setSerialNumber(SbomJson.serialNumber(serialSeed.toString()));
        Set<String> packed = new LinkedHashSet<>();
        components.forEach(component -> SbomChecks.check(packed.add(component.getBomRef()), "The jar packs two libraries that are the same component: " + component.getBomRef()));

        JsonNode json = BomGeneratorFactory.createJson(MavenComponents.SPEC_VERSION, bom).toJsonNode();
        SbomChecks.check(json instanceof ObjectNode, "The SBOM could not be written as JSON");
        SbomJson.putDependencies((ObjectNode) json, packedGraph(graph, root.getBomRef(), packed));
        return (ObjectNode) json;
    }

    /**
     * The graph between the root and the packed libraries only. What depended on an artifact that is not packed depends on
     * what that artifact depended on instead, and a packed library that the graph does not have is a dependency of the root.
     */
    static Map<String, Set<String>> packedGraph(Map<String, Set<String>> graph, String rootRef, Set<String> packed) {
        Map<String, Set<String>> result = new LinkedHashMap<>();
        result.put(rootRef, new LinkedHashSet<>(graph.getOrDefault(rootRef, Set.of())));
        graph.forEach((ref, dependsOn) -> result.putIfAbsent(ref, new LinkedHashSet<>(dependsOn)));

        Set<String> removed = new LinkedHashSet<>(result.keySet());
        removed.remove(rootRef);
        removed.removeAll(packed);
        // Only removed artifacts have edges here, so following them stops at the first artifact that stays
        Map<String, Set<String>> removedDependsOn = new HashMap<>();
        removed.forEach(ref -> removedDependsOn.put(ref, result.get(ref)));
        result.keySet().removeAll(removed);
        result.forEach((ref, dependsOn) -> {
            Set<String> reached = new LinkedHashSet<>();
            dependsOn.stream().filter(removed::contains).toList().forEach(target -> SbomChecks.reachableFrom(target, removedDependsOn, reached));
            dependsOn.addAll(reached);
            dependsOn.removeAll(removed);
            dependsOn.remove(ref);
        });
        for (String ref : packed) {
            if (result.putIfAbsent(ref, new LinkedHashSet<>()) == null) {
                result.get(rootRef).add(ref);
            }
        }
        return result;
    }

    private static Property property(String name, String value) {
        Property property = new Property();
        property.setName(name);
        property.setValue(value);
        return property;
    }
}
