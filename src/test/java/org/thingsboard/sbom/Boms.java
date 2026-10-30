package org.thingsboard.sbom;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

final class Boms {

    static final ObjectMapper MAPPER = new ObjectMapper();
    static final String HOST_PREFIX = "pkg:maven/org.thingsboard/ui-ngx@";

    private Boms() {
    }

    static ObjectNode fixture(String name) {
        try (InputStream in = Boms.class.getResourceAsStream("/fixtures/" + name)) {
            return (ObjectNode) MAPPER.readTree(in);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    static ObjectNode mavenFixture() {
        return fixture("maven-application.cdx.json");
    }

    static ObjectNode npmFixture() {
        return fixture("npm-ui-ngx.cdx.json");
    }

    static ObjectNode bom(String specVersion, String rootRef) {
        ObjectNode bom = MAPPER.createObjectNode();
        bom.put("bomFormat", "CycloneDX");
        bom.put("specVersion", specVersion);
        bom.put("version", 1);
        bom.putObject("metadata").putObject("component")
                .put("type", "application")
                .put("bom-ref", rootRef)
                .put("name", rootRef);
        bom.putArray("components");
        bom.putArray("dependencies");
        return bom;
    }

    static ObjectNode component(ObjectNode bom, String ref, String purl) {
        return ((ArrayNode) bom.get("components")).addObject()
                .put("type", "library")
                .put("bom-ref", ref)
                .put("name", ref)
                .put("purl", purl);
    }

    static void dependency(ObjectNode bom, String ref, String... dependsOn) {
        ObjectNode entry = ((ArrayNode) bom.get("dependencies")).addObject().put("ref", ref);
        if (dependsOn.length > 0) {
            ArrayNode targets = entry.putArray("dependsOn");
            for (String target : dependsOn) {
                targets.add(target);
            }
        }
    }

    static ObjectNode simpleTarget() {
        ObjectNode bom = bom("1.6", "app");
        component(bom, "ui", HOST_PREFIX + "1.0?type=jar");
        component(bom, "lib", "pkg:maven/org.example/lib@1.0?type=jar");
        dependency(bom, "app", "ui", "lib");
        dependency(bom, "ui");
        dependency(bom, "lib");
        return bom;
    }

    static ObjectNode simpleNested() {
        ObjectNode bom = bom("1.6", "npm-root");
        component(bom, "a", "pkg:npm/a@1.0.0");
        component(bom, "b", "pkg:npm/b@2.0.0");
        dependency(bom, "npm-root", "a");
        dependency(bom, "a", "b");
        dependency(bom, "b");
        return bom;
    }

    static Map<String, Set<String>> graph(JsonNode bom) {
        Map<String, Set<String>> graph = new HashMap<>();
        for (JsonNode dependency : bom.path("dependencies")) {
            Set<String> targets = graph.computeIfAbsent(dependency.path("ref").asText(), ref -> new HashSet<>());
            dependency.path("dependsOn").forEach(target -> targets.add(target.asText()));
        }
        return graph;
    }

    static Set<String> reachable(JsonNode bom, String start) {
        Map<String, Set<String>> graph = graph(bom);
        Set<String> seen = new HashSet<>();
        Deque<String> queue = new ArrayDeque<>(List.of(start));
        while (!queue.isEmpty()) {
            String ref = queue.pop();
            if (seen.add(ref)) {
                queue.addAll(graph.getOrDefault(ref, Set.of()));
            }
        }
        return seen;
    }

    static String hostRef(JsonNode bom) {
        for (JsonNode component : bom.path("components")) {
            if (component.path("purl").asText().startsWith(HOST_PREFIX)) {
                return component.path("bom-ref").asText();
            }
        }
        throw new IllegalStateException("No host component");
    }

}
