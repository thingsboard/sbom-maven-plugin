package org.thingsboard.sbom;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.cyclonedx.Version;
import org.cyclonedx.parsers.JsonParser;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.StreamSupport;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.thingsboard.sbom.Boms.HOST_PREFIX;
import static org.thingsboard.sbom.Boms.component;
import static org.thingsboard.sbom.Boms.dependency;
import static org.thingsboard.sbom.Boms.hostRef;
import static org.thingsboard.sbom.Boms.mavenFixture;
import static org.thingsboard.sbom.Boms.npmFixture;
import static org.thingsboard.sbom.Boms.simpleNested;
import static org.thingsboard.sbom.Boms.simpleTarget;

class SbomMergerTest {

    @Test
    void mergedComponentsAreTheUnionOfBothInputs() {
        ObjectNode target = mavenFixture();
        ObjectNode nested = npmFixture();

        JsonNode merged = SbomMerger.merge(target, nested, HOST_PREFIX);

        Set<String> expected = new HashSet<>(SbomChecks.componentRefs(target));
        expected.addAll(SbomChecks.componentRefs(nested));
        assertThat(SbomChecks.componentRefs(merged)).isEqualTo(expected);
        assertThat(merged.path("components").size()).isEqualTo(target.path("components").size() + nested.path("components").size());
    }

    @Test
    void nestedComponentsAreCopiedUnchanged() {
        ObjectNode nested = npmFixture();

        JsonNode merged = SbomMerger.merge(mavenFixture(), nested, HOST_PREFIX);

        for (JsonNode component : nested.path("components")) {
            assertThat(findComponent(merged, component.path("bom-ref").asText())).isEqualTo(component);
        }
    }

    @Test
    void hostComponentDependsOnTheDirectDependenciesOfTheNestedRoot() {
        ObjectNode target = mavenFixture();
        ObjectNode nested = npmFixture();

        JsonNode merged = SbomMerger.merge(target, nested, HOST_PREFIX);

        Set<String> nestedRootDependsOn = Boms.graph(nested).get(SbomChecks.rootRef(nested));
        assertThat(nestedRootDependsOn).isNotEmpty();
        assertThat(Boms.graph(merged).get(hostRef(target))).isEqualTo(nestedRootDependsOn);
    }

    @Test
    void everyNestedComponentIsReachableFromTheHostAndTheApplicationRoot() {
        ObjectNode target = mavenFixture();
        ObjectNode nested = npmFixture();

        JsonNode merged = SbomMerger.merge(target, nested, HOST_PREFIX);

        assertThat(Boms.reachable(merged, hostRef(target))).containsAll(SbomChecks.componentRefs(nested));
        assertThat(Boms.reachable(merged, SbomChecks.rootRef(target))).containsAll(SbomChecks.componentRefs(merged));
    }

    @Test
    void nestedRootDisappearsFromTheMergedSbom() {
        ObjectNode nested = npmFixture();
        String nestedRootRef = SbomChecks.rootRef(nested);

        JsonNode merged = SbomMerger.merge(mavenFixture(), nested, HOST_PREFIX);

        assertThat(merged.toString()).doesNotContain("\"" + nestedRootRef + "\"");
    }

    @Test
    void nestedDependencyEdgesArePreserved() {
        ObjectNode nested = npmFixture();
        String nestedRootRef = SbomChecks.rootRef(nested);

        JsonNode merged = SbomMerger.merge(mavenFixture(), nested, HOST_PREFIX);

        Map<String, Set<String>> mergedGraph = Boms.graph(merged);
        Boms.graph(nested).forEach((ref, targets) -> {
            if (!ref.equals(nestedRootRef)) {
                assertThat(mergedGraph.get(ref)).as("dependsOn of %s", ref).isEqualTo(targets);
            }
        });
    }

    @Test
    void targetDependencyEdgesArePreservedApartFromTheHost() {
        ObjectNode target = mavenFixture();
        String hostRef = hostRef(target);

        JsonNode merged = SbomMerger.merge(target, npmFixture(), HOST_PREFIX);

        Map<String, Set<String>> mergedGraph = Boms.graph(merged);
        Boms.graph(target).forEach((ref, targets) -> {
            if (ref.equals(hostRef)) {
                assertThat(mergedGraph.get(ref)).containsAll(targets);
            } else {
                assertThat(mergedGraph.get(ref)).as("dependsOn of %s", ref).isEqualTo(targets);
            }
        });
    }

    @Test
    void documentIdentityAndMetadataComponentAreKept() {
        ObjectNode target = mavenFixture();

        JsonNode merged = SbomMerger.merge(target, npmFixture(), HOST_PREFIX);

        for (String field : List.of("bomFormat", "specVersion", "serialNumber", "version")) {
            assertThat(merged.path(field)).as(field).isEqualTo(target.path(field));
        }
        assertThat(merged.path("metadata").path("component")).isEqualTo(target.path("metadata").path("component"));
        assertThat(merged.path("metadata").path("lifecycles")).isEqualTo(target.path("metadata").path("lifecycles"));
        assertThat(merged.path("metadata").path("properties")).isEqualTo(target.path("metadata").path("properties"));
    }

    @Test
    void toolsOfBothGeneratorsAreListedOnce() {
        ObjectNode target = mavenFixture();
        ObjectNode nested = npmFixture();

        JsonNode merged = SbomMerger.merge(target, nested, HOST_PREFIX);

        List<String> toolNames = StreamSupport.stream(merged.path("metadata").path("tools").path("components").spliterator(), false)
                .map(tool -> tool.path("name").asText())
                .toList();
        assertThat(toolNames).containsExactly("cyclonedx-maven-plugin", "npm", "cyclonedx-library", "cyclonedx-npm");
    }

    @Test
    void componentsWithTheSameNameAndDifferentPathsStayDistinct() {
        ObjectNode nested = npmFixture();
        long tslibCount = StreamSupport.stream(nested.path("components").spliterator(), false)
                .filter(component -> component.path("name").asText().equals("tslib"))
                .count();
        assertThat(tslibCount).isGreaterThan(1);

        JsonNode merged = SbomMerger.merge(mavenFixture(), nested, HOST_PREFIX);

        assertThat(StreamSupport.stream(merged.path("components").spliterator(), false)
                .filter(component -> component.path("name").asText().equals("tslib"))
                .count()).isEqualTo(tslibCount);
    }

    @Test
    void inputsAreNotModified() {
        ObjectNode target = mavenFixture();
        ObjectNode nested = npmFixture();

        SbomMerger.merge(target, nested, HOST_PREFIX);

        assertThat(target).isEqualTo(mavenFixture());
        assertThat(nested).isEqualTo(npmFixture());
    }

    @Test
    void mergingTwiceGivesTheSameResult() {
        ObjectNode once = SbomMerger.merge(mavenFixture(), npmFixture(), HOST_PREFIX);

        ObjectNode twice = SbomMerger.merge(once, npmFixture(), HOST_PREFIX);

        assertThat(twice).isEqualTo(once);
    }

    @Test
    void mergedSbomIsValidAgainstTheCycloneDxSchema() throws Exception {
        ObjectNode merged = SbomMerger.merge(mavenFixture(), npmFixture(), HOST_PREFIX);

        assertThat(new JsonParser().validate(merged, Version.VERSION_16)).isEmpty();
    }

    @Test
    void noEmptyDependsOnArraysAreCreated() {
        JsonNode merged = SbomMerger.merge(simpleTarget(), simpleNested(), HOST_PREFIX);

        for (JsonNode dependency : merged.path("dependencies")) {
            assertThat(dependency.has("dependsOn") && dependency.path("dependsOn").isEmpty())
                    .as("empty dependsOn on %s", dependency.path("ref").asText())
                    .isFalse();
        }
    }

    @Test
    void referencesToTheNestedRootInsideTheNestedGraphPointToTheHost() {
        ObjectNode nested = simpleNested();
        ((ObjectNode) nested.get("dependencies").get(2)).putArray("dependsOn").add("npm-root");

        JsonNode merged = SbomMerger.merge(simpleTarget(), nested, HOST_PREFIX);

        assertThat(Boms.graph(merged).get("b")).containsExactly("ui");
    }

    @Test
    void identicalComponentPresentInBothInputsIsKeptOnce() {
        ObjectNode target = simpleTarget();
        ObjectNode nested = simpleNested();
        component(target, "b", "pkg:npm/b@2.0.0");
        dependency(target, "b");
        ((ArrayNode) target.get("dependencies").get(0).get("dependsOn")).add("b");

        JsonNode merged = SbomMerger.merge(target, nested, HOST_PREFIX);

        assertThat(merged.path("components").size()).isEqualTo(4);
    }

    @Test
    void failsWhenAComponentConflictsWithADifferentComponentWithTheSameRef() {
        ObjectNode target = simpleTarget();
        component(target, "b", "pkg:npm/b@3.0.0");
        dependency(target, "b");

        assertThatThrownBy(() -> SbomMerger.merge(target, simpleNested(), HOST_PREFIX))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("Nested component b conflicts");
    }

    @Test
    void failsWhenTheHostComponentIsMissing() {
        assertThatThrownBy(() -> SbomMerger.merge(simpleTarget(), simpleNested(), "pkg:maven/org.thingsboard/missing@"))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("Expected exactly one target component with purl starting with pkg:maven/org.thingsboard/missing@, found []");
    }

    @Test
    void failsWhenTheHostComponentIsAmbiguous() {
        ObjectNode target = simpleTarget();
        component(target, "ui2", HOST_PREFIX + "2.0?type=jar");
        dependency(target, "ui2");

        assertThatThrownBy(() -> SbomMerger.merge(target, simpleNested(), HOST_PREFIX))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("found [ui, ui2]");
    }

    @Test
    void failsWhenTheHostPurlPrefixIsBlank() {
        assertThatThrownBy(() -> SbomMerger.merge(simpleTarget(), simpleNested(), " "))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("Host purl prefix is blank");
    }

    @Test
    void failsWhenSpecVersionsDiffer() {
        ObjectNode nested = simpleNested();
        nested.put("specVersion", "1.5");

        assertThatThrownBy(() -> SbomMerger.merge(simpleTarget(), nested, HOST_PREFIX))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("Spec versions differ: target SBOM is 1.6, nested SBOM is 1.5");
    }

    @Test
    void failsOnAnUnsupportedSpecVersion() {
        ObjectNode target = simpleTarget();
        target.put("specVersion", "9.9");

        assertThatThrownBy(() -> SbomMerger.merge(target, simpleNested(), HOST_PREFIX))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("Target SBOM has unsupported specVersion '9.9'");
    }

    @Test
    void failsWhenAnInputIsNotCycloneDx() {
        ObjectNode nested = simpleNested();
        nested.put("bomFormat", "SPDX");

        assertThatThrownBy(() -> SbomMerger.merge(simpleTarget(), nested, HOST_PREFIX))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("Nested SBOM is not a CycloneDX document");
    }

    @Test
    void failsWhenAnInputIsNotAJsonObject() {
        assertThatThrownBy(() -> SbomMerger.merge(simpleTarget(), Boms.MAPPER.createArrayNode(), HOST_PREFIX))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("Nested SBOM is not a JSON object");
    }

    @Test
    void failsWhenAnInputViolatesTheSchema() {
        ObjectNode nested = simpleNested();
        ((ObjectNode) nested.get("components").get(0)).remove("name");

        assertThatThrownBy(() -> SbomMerger.merge(simpleTarget(), nested, HOST_PREFIX))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("Nested SBOM is not valid against the CycloneDX 1.6 schema")
                .hasMessageContaining("name");
    }

    @Test
    void failsWhenAnInputHasNoRootBomRef() {
        ObjectNode target = simpleTarget();
        ((ObjectNode) target.get("metadata").get("component")).remove("bom-ref");

        assertThatThrownBy(() -> SbomMerger.merge(target, simpleNested(), HOST_PREFIX))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("Target SBOM has no metadata.component.bom-ref");
    }

    @Test
    void failsOnTheLegacyToolsArray() {
        ObjectNode nested = simpleNested();
        ((ObjectNode) nested.get("metadata")).putArray("tools").addObject().put("name", "old-tool");

        assertThatThrownBy(() -> SbomMerger.merge(simpleTarget(), nested, HOST_PREFIX))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("legacy metadata.tools array");
    }

    @Test
    void failsWhenAnInputHasDuplicateBomRefs() {
        ObjectNode target = simpleTarget();
        component(target, "lib", "pkg:maven/org.example/lib@2.0?type=jar");

        assertThatThrownBy(() -> SbomMerger.merge(target, simpleNested(), HOST_PREFIX))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("Target SBOM has duplicate component bom-refs: [lib]");
    }

    @Test
    void failsWhenAnInputHasADanglingDependency() {
        ObjectNode nested = simpleNested();
        ((ArrayNode) nested.get("dependencies").get(1).get("dependsOn")).add("ghost");

        assertThatThrownBy(() -> SbomMerger.merge(simpleTarget(), nested, HOST_PREFIX))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("Nested SBOM: a depends on unknown ref ghost");
    }

    @Test
    void failsWhenAnInputHasADependencyEntryForAnUnknownRef() {
        ObjectNode nested = simpleNested();
        dependency(nested, "ghost");

        assertThatThrownBy(() -> SbomMerger.merge(simpleTarget(), nested, HOST_PREFIX))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("Nested SBOM has a dependency entry for unknown ref ghost");
    }

    @Test
    void failsWhenAnInputHasTwoIdenticalDependencyEntries() {
        ObjectNode nested = simpleNested();
        dependency(nested, "b");

        assertThatThrownBy(() -> SbomMerger.merge(simpleTarget(), nested, HOST_PREFIX))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("Nested SBOM is not valid against the CycloneDX 1.6 schema")
                .hasMessageContaining("unique");
    }

    @Test
    void failsWhenAnInputHasTwoDifferentDependencyEntriesForTheSameRef() {
        ObjectNode nested = simpleNested();
        dependency(nested, "b", "a");

        assertThatThrownBy(() -> SbomMerger.merge(simpleTarget(), nested, HOST_PREFIX))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("Nested SBOM has more than one dependency entry for b");
    }

    @Test
    void failsWhenTheNestedSbomHasNoComponents() {
        ObjectNode nested = Boms.bom("1.6", "npm-root");
        dependency(nested, "npm-root");

        assertThatThrownBy(() -> SbomMerger.merge(simpleTarget(), nested, HOST_PREFIX))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("Nested SBOM has no components");
    }

    @Test
    void failsWhenTheNestedRootHasNoDirectDependencies() {
        ObjectNode nested = simpleNested();
        ((ObjectNode) nested.get("dependencies").get(0)).remove("dependsOn");

        assertThatThrownBy(() -> SbomMerger.merge(simpleTarget(), nested, HOST_PREFIX))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("Nested SBOM root npm-root has no direct dependencies");
    }

    @Test
    void failsWhenTheNestedRootIsAlsoAComponent() {
        ObjectNode nested = simpleNested();
        component(nested, "npm-root", "pkg:npm/npm-root@1.0.0");

        assertThatThrownBy(() -> SbomMerger.merge(simpleTarget(), nested, HOST_PREFIX))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("Nested SBOM lists its own root npm-root as a component");
    }

    @Test
    void failsWhenANestedComponentIsNotReachableFromTheNestedRoot() {
        ObjectNode nested = simpleNested();
        component(nested, "orphan", "pkg:npm/orphan@1.0.0");
        dependency(nested, "orphan");

        assertThatThrownBy(() -> SbomMerger.merge(simpleTarget(), nested, HOST_PREFIX))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("Nested components are not reachable from host component ui: [orphan]");
    }

    private static JsonNode findComponent(JsonNode bom, String ref) {
        for (JsonNode component : bom.path("components")) {
            if (component.path("bom-ref").asText().equals(ref)) {
                return component;
            }
        }
        return null;
    }

}
