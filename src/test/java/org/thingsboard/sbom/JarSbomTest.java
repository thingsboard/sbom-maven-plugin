// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
package org.thingsboard.sbom;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.cyclonedx.model.Component;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JarSbomTest {

    private static final String ROOT = "pkg:maven/org.example/app@1.0?type=jar";
    private static final String A = "pkg:maven/org.example/a@1.0?type=jar";
    private static final String B = "pkg:maven/org.example/b@1.0?type=jar";
    private static final String C = "pkg:maven/org.example/c@1.0?type=jar";
    private static final String STARTER = "pkg:maven/org.example/starter@1.0?type=jar";

    @Test
    void theGraphOfPackedLibrariesIsKeptAsItIs() {
        Map<String, Set<String>> graph = graph(ROOT, Set.of(A), A, Set.of(B), B, Set.of());

        assertThat(JarSbom.packedGraph(graph, ROOT, Set.of(A, B))).isEqualTo(graph);
    }

    @Test
    void whatDependedOnAnArtifactThatIsNotPackedDependsOnWhatItDependedOn() {
        Map<String, Set<String>> graph = graph(ROOT, Set.of(STARTER), STARTER, Set.of(A, B), A, Set.of(), B, Set.of());

        assertThat(JarSbom.packedGraph(graph, ROOT, Set.of(A, B))).isEqualTo(graph(ROOT, Set.of(A, B), A, Set.of(), B, Set.of()));
    }

    @Test
    void artifactsThatAreNotPackedAndDependOnEachOtherAreLeftOutTogether() {
        Map<String, Set<String>> graph = graph(ROOT, Set.of(STARTER), STARTER, Set.of(C), C, Set.of(STARTER, A), A, Set.of());

        assertThat(JarSbom.packedGraph(graph, ROOT, Set.of(A))).isEqualTo(graph(ROOT, Set.of(A), A, Set.of()));
    }

    @Test
    void aLibraryDoesNotDependOnItselfThroughAnArtifactThatIsNotPacked() {
        Map<String, Set<String>> graph = graph(ROOT, Set.of(A), A, Set.of(STARTER), STARTER, Set.of(A));

        assertThat(JarSbom.packedGraph(graph, ROOT, Set.of(A))).isEqualTo(graph(ROOT, Set.of(A), A, Set.of()));
    }

    @Test
    void aPackedLibraryThatTheGraphDoesNotHaveIsADependencyOfTheRoot() {
        Map<String, Set<String>> graph = graph(ROOT, Set.of(A), A, Set.of());

        assertThat(JarSbom.packedGraph(graph, ROOT, Set.of(A, B))).isEqualTo(graph(ROOT, Set.of(A, B), A, Set.of(), B, Set.of()));
    }

    @Test
    void theSbomIsValidAndListsTheRootTheToolTheLibrariesAndTheirGraph() {
        ObjectNode bom = JarSbom.bom(component("app", ROOT), component("sbom-maven-plugin", null), List.of(component("a", A), component("b", B)),
                graph(ROOT, Set.of(STARTER), STARTER, Set.of(A), A, Set.of(B), B, Set.of()), true);

        SbomChecks.checkInput("Jar", bom);
        assertThat(bom.path("specVersion").asText()).isEqualTo("1.6");
        assertThat(bom.path("metadata").path("component").path("bom-ref").asText()).isEqualTo(ROOT);
        assertThat(bom.path("metadata").path("tools").path("components")).extracting(tool -> tool.path("name").asText()).containsExactly("sbom-maven-plugin");
        assertThat(bom.path("metadata").path("lifecycles")).extracting(lifecycle -> lifecycle.path("phase").asText()).containsExactly("build");
        assertThat(bom.path("metadata").path("properties")).extracting(property -> property.path("name").asText() + "=" + property.path("value").asText())
                .containsExactly("maven.goal=jar", "cdx:reproducible=enabled");
        assertThat(bom.path("components")).extracting(component -> component.path("bom-ref").asText()).containsExactly(A, B);
        assertThat(SbomChecks.dependencyGraph(bom)).isEqualTo(graph(ROOT, Set.of(A), A, Set.of(B), B, Set.of()));
    }

    @Test
    void theSerialNumberIsTheSameForTheSameProjectAndDiffersWithItsVersion() {
        JsonNode first = JarSbom.bom(component("app", ROOT), component("tool", null), List.of(), Map.of(), false);
        JsonNode second = JarSbom.bom(component("app", ROOT), component("tool", null), List.of(), Map.of(), false);
        Component newer = component("app", ROOT);
        newer.setVersion("2.0");
        JsonNode third = JarSbom.bom(newer, component("tool", null), List.of(), Map.of(), false);

        assertThat(first.path("serialNumber").asText()).startsWith("urn:uuid:").isEqualTo(second.path("serialNumber").asText())
                .isNotEqualTo(third.path("serialNumber").asText());
        assertThat(first.path("metadata").path("properties")).hasSize(1);
    }

    @Test
    void twoLibrariesThatAreTheSameComponentAreRefused() {
        assertThatThrownBy(() -> JarSbom.bom(component("app", ROOT), component("tool", null), List.of(component("a", A), component("a", A)), Map.of(), false))
                .isInstanceOf(SbomException.class).hasMessageContaining("two libraries that are the same component: " + A);
    }

    private static Component component(String name, String ref) {
        Component component = new Component();
        component.setType(Component.Type.LIBRARY);
        component.setGroup("org.example");
        component.setName(name);
        component.setVersion("1.0");
        component.setPurl(ref);
        component.setBomRef(ref);
        return component;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Set<String>> graph(Object... refsAndDependencies) {
        Map<String, Set<String>> graph = new LinkedHashMap<>();
        for (int i = 0; i < refsAndDependencies.length; i += 2) {
            graph.put((String) refsAndDependencies[i], new LinkedHashSet<>((Set<String>) refsAndDependencies[i + 1]));
        }
        return graph;
    }

}
