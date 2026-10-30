package org.thingsboard.sbom;

import com.fasterxml.jackson.databind.JsonNode;
import org.cyclonedx.Version;
import org.cyclonedx.exception.ParseException;
import org.cyclonedx.parsers.JsonParser;

import java.io.IOException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

final class SbomChecks {

    private SbomChecks() {
    }

    static void checkInput(String label, JsonNode bom) {
        check(bom != null && bom.isObject(), label + " SBOM is not a JSON object");
        check("CycloneDX".equals(bom.path("bomFormat").asText()), label + " SBOM is not a CycloneDX document");
        checkSchema(label, bom);
        check(!rootRef(bom).isEmpty(), label + " SBOM has no metadata.component.bom-ref");
        JsonNode tools = bom.path("metadata").path("tools");
        check(tools.isMissingNode() || tools.isObject(), label + " SBOM uses the legacy metadata.tools array, which is not supported");
        checkStructure(label, bom);
    }

    static void checkSameSpecVersion(JsonNode target, JsonNode nested) {
        String targetVersion = target.path("specVersion").asText();
        String nestedVersion = nested.path("specVersion").asText();
        check(targetVersion.equals(nestedVersion),
                "Spec versions differ: target SBOM is " + targetVersion + ", nested SBOM is " + nestedVersion);
    }

    static String findHostRef(JsonNode target, String hostPurlPrefix) {
        check(!hostPurlPrefix.isBlank(), "Host purl prefix is blank");
        List<String> hosts = new ArrayList<>();
        for (JsonNode component : target.path("components")) {
            if (component.path("purl").asText().startsWith(hostPurlPrefix)) {
                hosts.add(component.path("bom-ref").asText());
            }
        }
        check(hosts.size() == 1, "Expected exactly one target component with purl starting with " + hostPurlPrefix + ", found " + hosts);
        check(!hosts.get(0).isEmpty(), "Host component " + hostPurlPrefix + " has no bom-ref");
        return hosts.get(0);
    }

    static String checkNestedRoot(JsonNode nested) {
        String rootRef = rootRef(nested);
        check(nested.path("components").size() > 0, "Nested SBOM has no components");
        check(!componentRefs(nested).contains(rootRef), "Nested SBOM lists its own root " + rootRef + " as a component");
        JsonNode rootDependency = dependencyEntries(nested).get(rootRef);
        check(rootDependency != null && rootDependency.path("dependsOn").size() > 0,
                "Nested SBOM root " + rootRef + " has no direct dependencies");
        return rootRef;
    }

    static void checkOutput(JsonNode target, JsonNode nested, JsonNode merged, String hostRef, String nestedRootRef) {
        checkInput("Merged", merged);
        for (String field : List.of("bomFormat", "specVersion", "serialNumber", "version")) {
            check(target.path(field).equals(merged.path(field)), "Merged SBOM changed " + field);
        }
        check(target.path("metadata").path("component").equals(merged.path("metadata").path("component")),
                "Merged SBOM changed metadata.component");

        Set<String> expectedRefs = new HashSet<>(componentRefs(target));
        expectedRefs.addAll(componentRefs(nested));
        check(componentRefs(merged).equals(expectedRefs), "Merged SBOM components are not the union of the target and nested components");
        check(!componentRefs(merged).contains(nestedRootRef) && !dependencyEntries(merged).containsKey(nestedRootRef),
                "Merged SBOM still references the nested root " + nestedRootRef);

        Map<String, JsonNode> mergedDependencies = dependencyEntries(merged);
        Set<String> hostDependsOn = dependsOn(mergedDependencies.get(hostRef));
        Set<String> nestedRootDependsOn = dependsOn(dependencyEntries(nested).get(nestedRootRef));
        check(!hostDependsOn.isEmpty() && hostDependsOn.containsAll(nestedRootDependsOn),
                "Host component " + hostRef + " does not depend on the direct dependencies of the nested root");

        Set<String> reachable = reachableFrom(hostRef, mergedDependencies);
        Set<String> unreachable = componentRefs(nested).stream().filter(ref -> !reachable.contains(ref)).collect(Collectors.toCollection(LinkedHashSet::new));
        check(unreachable.isEmpty(), "Nested components are not reachable from host component " + hostRef + ": " + unreachable);
    }

    static Set<String> componentRefs(JsonNode bom) {
        Set<String> refs = new LinkedHashSet<>();
        collectComponentRefs(bom.path("components"), refs, new ArrayList<>());
        return refs;
    }

    static String rootRef(JsonNode bom) {
        return bom.path("metadata").path("component").path("bom-ref").asText();
    }

    private static void checkSchema(String label, JsonNode bom) {
        String specVersion = bom.path("specVersion").asText();
        Version version = null;
        for (Version candidate : Version.values()) {
            if (candidate.getVersionString().equals(specVersion)) {
                version = candidate;
            }
        }
        check(version != null, label + " SBOM has unsupported specVersion '" + specVersion + "'");
        List<ParseException> errors;
        try {
            errors = new JsonParser().validate(bom, version);
        } catch (IOException e) {
            throw new SbomMergeException(label + " SBOM could not be validated against the CycloneDX " + specVersion + " schema", e);
        }
        check(errors.isEmpty(), label + " SBOM is not valid against the CycloneDX " + specVersion + " schema: "
                + errors.stream().map(Throwable::getMessage).collect(Collectors.joining("; ")));
    }

    private static void checkStructure(String label, JsonNode bom) {
        List<String> duplicates = new ArrayList<>();
        Set<String> refs = new LinkedHashSet<>();
        collectComponentRefs(bom.path("components"), refs, duplicates);
        check(duplicates.isEmpty(), label + " SBOM has duplicate component bom-refs: " + duplicates);
        check(!refs.contains(""), label + " SBOM has components without bom-ref");

        Set<String> known = new HashSet<>(refs);
        known.add(rootRef(bom));
        Set<String> dependencyRefs = new HashSet<>();
        for (JsonNode dependency : bom.path("dependencies")) {
            String ref = dependency.path("ref").asText();
            check(dependencyRefs.add(ref), label + " SBOM has more than one dependency entry for " + ref);
            check(known.contains(ref), label + " SBOM has a dependency entry for unknown ref " + ref);
            for (JsonNode target : dependency.path("dependsOn")) {
                check(known.contains(target.asText()), label + " SBOM: " + ref + " depends on unknown ref " + target.asText());
            }
        }
    }

    private static void collectComponentRefs(JsonNode components, Set<String> refs, List<String> duplicates) {
        for (JsonNode component : components) {
            String ref = component.path("bom-ref").asText();
            if (!refs.add(ref)) {
                duplicates.add(ref);
            }
            collectComponentRefs(component.path("components"), refs, duplicates);
        }
    }

    private static Map<String, JsonNode> dependencyEntries(JsonNode bom) {
        Map<String, JsonNode> entries = new HashMap<>();
        bom.path("dependencies").forEach(dependency -> entries.put(dependency.path("ref").asText(), dependency));
        return entries;
    }

    private static Set<String> dependsOn(JsonNode dependency) {
        Set<String> refs = new HashSet<>();
        if (dependency != null) {
            dependency.path("dependsOn").forEach(ref -> refs.add(ref.asText()));
        }
        return refs;
    }

    private static Set<String> reachableFrom(String start, Map<String, JsonNode> dependencies) {
        Set<String> reachable = new HashSet<>();
        Deque<String> queue = new ArrayDeque<>(List.of(start));
        while (!queue.isEmpty()) {
            String ref = queue.pop();
            if (reachable.add(ref)) {
                queue.addAll(dependsOn(dependencies.get(ref)));
            }
        }
        return reachable;
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new SbomMergeException(message);
        }
    }

}
