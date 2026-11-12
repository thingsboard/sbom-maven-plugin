// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
package org.thingsboard.sbom;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import org.thingsboard.sbom.JarLibraries.Library;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.function.Function;

/**
 * Makes the Maven libraries of an SBOM equal to the libraries packed in a jar.
 * A component and a packed library are the same thing when their SHA-256 hashes are equal, or else when the file has
 * the name Maven gives the component: {@code <artifactId>-<version>[-<classifier>].jar}.
 * <ul>
 * <li>A packed library without a component gets one, from {@code identify}; when {@code identify} does not know it, the SBOM is refused.</li>
 * <li>A component without a packed library is removed, and what depended on it depends on its dependencies instead.</li>
 * <li>A component whose hashes differ from those of its packed library gets the hashes of the packed library.</li>
 * </ul>
 * Only Maven components of type {@code jar} are compared; every other component is left as it is.
 */
final class SbomReconciler {

    /**
     * What a reconciliation changed, as component references and file names.
     */
    record Result(ObjectNode bom, List<String> added, List<String> removed, List<String> rehashed) {

        boolean changed() {
            return !added.isEmpty() || !removed.isEmpty() || !rehashed.isEmpty();
        }

    }

    private SbomReconciler() {}

    /**
     * @param identify gives the component of a packed library that the SBOM does not list, without {@code hashes}
     */
    static Result reconcile(JsonNode source, List<Library> libraries, Function<Library, Optional<ObjectNode>> identify) {
        SbomChecks.checkInput("Source", source);
        ObjectNode bom = (ObjectNode) source.deepCopy();
        ArrayNode components = bom.withArrayProperty("components");

        Map<String, ObjectNode> bySha256 = new HashMap<>();
        Map<String, ObjectNode> byFileName = new HashMap<>();
        Set<String> unmatched = new LinkedHashSet<>();
        for (JsonNode node : components) {
            ObjectNode component = (ObjectNode) node;
            String fileName = fileName(component);
            if (fileName == null) {
                continue;
            }
            unmatched.add(ref(component));
            byFileName.putIfAbsent(fileName, component);
            String sha256 = sha256(component);
            if (sha256 != null) {
                bySha256.putIfAbsent(sha256, component);
            }
        }

        List<String> added = new ArrayList<>();
        List<String> rehashed = new ArrayList<>();
        List<String> unknown = new ArrayList<>();
        List<ObjectNode> newComponents = new ArrayList<>();
        for (Library library : libraries) {
            ObjectNode component = bySha256.get(library.sha256());
            if (component == null || !unmatched.contains(ref(component))) {
                component = byFileName.get(library.fileName());
            }
            if (component != null && unmatched.remove(ref(component))) {
                if (!library.sha256().equals(sha256(component))) {
                    component.set("hashes", SbomJson.hashesJson(library.hashes()));
                    rehashed.add(ref(component));
                }
                continue;
            }
            Optional<ObjectNode> identified = identify.apply(library);
            if (identified.isEmpty()) {
                unknown.add(library.fileName());
                continue;
            }
            ObjectNode newComponent = identified.get();
            newComponent.set("hashes", SbomJson.hashesJson(library.hashes()));
            newComponents.add(newComponent);
            added.add(ref(newComponent));
        }
        SbomChecks.check(unknown.isEmpty(), "The jar packs libraries that the SBOM does not list and that are not Maven dependencies of the project: "
                + String.join(", ", unknown) + ". Declare each of them in the libraries parameter of the goal");

        if (added.isEmpty() && unmatched.isEmpty() && rehashed.isEmpty()) {
            return new Result(bom, added, List.of(), rehashed);
        }

        Map<String, Set<String>> graph = SbomChecks.dependencyGraph(bom);
        String rootRef = SbomChecks.rootRef(bom);
        Set<String> refs = SbomChecks.componentRefs(bom);
        for (ObjectNode newComponent : newComponents) {
            String newRef = ref(newComponent);
            SbomChecks.check(refs.add(newRef), "The component of a packed library clashes with a component that is already in the SBOM: " + newRef);
            Set<String> parents = parentsOfSibling(newComponent, components, graph);
            components.add(newComponent);
            graph.putIfAbsent(newRef, new LinkedHashSet<>());
            (parents.isEmpty() ? Set.of(rootRef) : parents).forEach(parent -> graph.computeIfAbsent(parent, key -> new LinkedHashSet<>()).add(newRef));
        }

        for (String removedRef : unmatched) {
            Set<String> targets = graph.getOrDefault(removedRef, Set.of());
            graph.remove(removedRef);
            for (Set<String> dependsOn : graph.values()) {
                if (dependsOn.remove(removedRef)) {
                    dependsOn.addAll(targets);
                }
            }
        }
        graph.forEach((from, dependsOn) -> dependsOn.remove(from));
        for (Iterator<JsonNode> iterator = components.iterator(); iterator.hasNext(); ) {
            if (unmatched.contains(ref(iterator.next()))) {
                iterator.remove();
            }
        }
        SbomJson.putDependencies(bom, graph);

        SbomChecks.checkInput("Reconciled", bom);
        return new Result(bom, added, new ArrayList<>(unmatched), rehashed);
    }

    /**
     * The name Maven gives the file of a component, or null for a component that is not a Maven jar.
     */
    static String fileName(JsonNode component) {
        PackageURL purl = SbomImage.parsePurl(component.path("purl").asText());
        if (purl == null || !PackageURL.StandardTypes.MAVEN.equals(purl.getType()) || purl.getVersion() == null) {
            return null;
        }
        Map<String, String> qualifiers = purl.getQualifiers() == null ? Map.of() : purl.getQualifiers();
        if (!"jar".equals(qualifiers.getOrDefault("type", "jar"))) {
            return null;
        }
        return fileName(purl.getName(), purl.getVersion(), qualifiers.get("classifier"));
    }

    static String fileName(String artifactId, String version, String classifier) {
        return artifactId + "-" + version + (classifier == null || classifier.isEmpty() ? "" : "-" + classifier) + ".jar";
    }

    /**
     * A component for a Maven jar, with the purl and reference that cyclonedx-maven-plugin gives such an artifact.
     */
    static ObjectNode mavenComponent(String group, String artifactId, String version, String classifier) {
        TreeMap<String, String> qualifiers = new TreeMap<>(Map.of("type", "jar"));
        if (classifier != null && !classifier.isEmpty()) {
            qualifiers.put("classifier", classifier);
        }
        String purl;
        try {
            purl = new PackageURL(PackageURL.StandardTypes.MAVEN, group, artifactId, version, qualifiers, null).canonicalize();
        } catch (MalformedPackageURLException e) {
            throw new SbomException("No purl can be made for " + group + ":" + artifactId + ":" + version, e);
        }
        ObjectNode component = JsonNodeFactory.instance.objectNode();
        component.put("type", "library");
        component.put("bom-ref", purl);
        component.put("group", group);
        component.put("name", artifactId);
        component.put("version", version);
        component.put("scope", "required");
        component.put("purl", purl);
        return component;
    }

    /**
     * Copies what the pom says from a listed component of the same group, name and version, which comes from the same pom.
     */
    static void copyPomFields(JsonNode bom, ObjectNode component) {
        for (JsonNode sibling : bom.path("components")) {
            if (sameCoordinates(sibling, component)) {
                SbomJson.copyFields(sibling, component, "publisher", "description", "licenses", "externalReferences");
                return;
            }
        }
    }

    private static boolean sameCoordinates(JsonNode a, JsonNode b) {
        return a.path("group").equals(b.path("group")) && a.path("name").equals(b.path("name")) && a.path("version").equals(b.path("version"));
    }

    /**
     * What depends on another artifact of the same group, name and version: such a component is packed for the same reason.
     */
    private static Set<String> parentsOfSibling(JsonNode component, ArrayNode components, Map<String, Set<String>> graph) {
        Set<String> parents = new LinkedHashSet<>();
        for (JsonNode candidate : components) {
            if (sameCoordinates(candidate, component)) {
                String siblingRef = ref(candidate);
                graph.forEach((from, dependsOn) -> {
                    if (dependsOn.contains(siblingRef)) {
                        parents.add(from);
                    }
                });
            }
        }
        return parents;
    }

    private static String ref(JsonNode component) {
        return component.path("bom-ref").asText();
    }

    private static String sha256(JsonNode component) {
        for (JsonNode hash : component.path("hashes")) {
            if ("SHA-256".equals(hash.path("alg").asText())) {
                return hash.path("content").asText().toLowerCase(Locale.ROOT);
            }
        }
        return null;
    }

}
