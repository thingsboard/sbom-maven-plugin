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
import java.util.HashSet;
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
     * Puts the libraries that the graph does not have into it, by what the poms say: such a library depends on the packed
     * libraries that its pom names, and the packed libraries whose pom names it depend on it. Maven's graph can lack a
     * dependency when the version that won a conflict sits under a test dependency.
     *
     * @param missing the bom-refs of the libraries to put into the graph
     * @param poms    what the pom of each packed library says, by the bom-ref of the library
     * @return the libraries that no pom of a packed library names; {@link #packedGraph} makes them dependencies of the root
     */
    static Set<String> linkByPoms(Map<String, Set<String>> graph, Set<String> missing, Map<String, MavenComponents.Pom> poms) {
        Map<String, String> refs = new HashMap<>();
        poms.forEach((ref, pom) -> refs.put(pom.coordinates(), ref));
        Set<String> withoutDependent = new LinkedHashSet<>(missing);
        for (String ref : missing) {
            MavenComponents.Pom own = poms.get(ref);
            Set<String> dependsOn = graph.computeIfAbsent(ref, key -> new LinkedHashSet<>());
            own.dependsOn().stream().map(refs::get).filter(target -> target != null && !target.equals(ref)).forEach(dependsOn::add);
            poms.forEach((dependent, pom) -> {
                if (!dependent.equals(ref) && pom.dependsOn().contains(own.coordinates())) {
                    graph.computeIfAbsent(dependent, key -> new LinkedHashSet<>()).add(ref);
                    withoutDependent.remove(ref);
                }
            });
        }
        return withoutDependent;
    }

    /**
     * The graph between the root and the packed libraries only. What depended on an artifact that is not packed depends on
     * what that artifact depended on instead, and a packed library that nothing depends on is a dependency of the root, so
     * every library is reached from the root.
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
        packed.forEach(ref -> result.putIfAbsent(ref, new LinkedHashSet<>()));
        Set<String> dependedOn = new HashSet<>();
        result.values().forEach(dependedOn::addAll);
        packed.stream().filter(ref -> !dependedOn.contains(ref)).forEach(result.get(rootRef)::add);
        // What is left out of reach is libraries that depend on each other in a circle and that nothing else depends on
        Set<String> reached = SbomChecks.reachableFrom(rootRef, result);
        for (String ref : packed) {
            if (!reached.contains(ref)) {
                result.get(rootRef).add(ref);
                SbomChecks.reachableFrom(ref, result, reached);
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
