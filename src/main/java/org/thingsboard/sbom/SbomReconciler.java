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
import java.util.function.Predicate;
import java.util.function.Supplier;

/**
 * Makes the Maven libraries of an SBOM equal to the libraries packed in a jar.
 * A component and a packed library are the same thing when their SHA-256 hashes are equal, or else when the file has
 * the name Maven gives the component: {@code <artifactId>-<version>[-<classifier>].jar}.
 * <ul>
 * <li>A packed library without a component gets one, from {@code identify}; when {@code identify} does not know it, the SBOM is refused.</li>
 * <li>A component without a packed library is removed, and what depended on it depends on its dependencies instead.</li>
 * <li>A component whose hashes differ from those of its packed library gets the hashes of the packed library.</li>
 * </ul>
 * Only Maven components whose file is a jar are compared (type {@code jar}, {@code test-jar} and the like); every other
 * component is left as it is.
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
     * @param jarType  tells whether the file of a Maven artifact type is a {@code .jar}
     * @param identify gives the component of a packed library that the SBOM does not list, without {@code hashes}
     */
    static Result reconcile(JsonNode source, List<Library> libraries, Predicate<String> jarType, Function<Library, Optional<ObjectNode>> identify) {
        SbomChecks.checkInput("Source", source);
        ObjectNode bom = (ObjectNode) source.deepCopy();
        ArrayNode components = bom.withArrayProperty("components");

        Map<String, List<ObjectNode>> bySha256 = new HashMap<>();
        Map<String, ObjectNode> byFileName = new HashMap<>();
        Set<String> unmatched = new LinkedHashSet<>();
        for (JsonNode node : components) {
            ObjectNode component = (ObjectNode) node;
            String fileName = fileName(component, jarType);
            if (fileName == null) {
                continue;
            }
            unmatched.add(ref(component));
            byFileName.putIfAbsent(fileName, component);
            String sha256 = sha256(component);
            if (sha256 != null) {
                bySha256.computeIfAbsent(sha256, key -> new ArrayList<>()).add(component);
            }
        }

        // The surest match first, so a library with the bytes of another one cannot take the component of that one
        List<Library> pending = new ArrayList<>(libraries);
        pending.removeIf(library -> {
            ObjectNode component = byFileName.get(library.fileName());
            return component != null && library.sha256().equals(sha256(component)) && unmatched.remove(ref(component));
        });
        pending.removeIf(library -> bySha256.getOrDefault(library.sha256(), List.of()).stream().anyMatch(component -> unmatched.remove(ref(component))));
        List<String> rehashed = new ArrayList<>();
        pending.removeIf(library -> {
            ObjectNode component = byFileName.get(library.fileName());
            if (component == null || !unmatched.remove(ref(component))) {
                return false;
            }
            component.set("hashes", SbomJson.hashesJson(library.hashes()));
            rehashed.add(ref(component));
            return true;
        });

        List<String> added = new ArrayList<>();
        List<String> unknown = new ArrayList<>();
        List<ObjectNode> newComponents = new ArrayList<>();
        for (Library library : pending) {
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

        unlink(graph, unmatched);
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
     * Takes components out of the graph: what depended on a removed component depends on what that component depended on,
     * through any number of removed components.
     */
    private static void unlink(Map<String, Set<String>> graph, Set<String> removed) {
        // Only removed components have edges here, so following them stops at the first component that stays
        Map<String, Set<String>> removedDependsOn = new HashMap<>();
        removed.forEach(ref -> removedDependsOn.put(ref, graph.getOrDefault(ref, Set.of())));
        graph.keySet().removeAll(removed);
        for (Set<String> dependsOn : graph.values()) {
            Set<String> reached = new LinkedHashSet<>();
            dependsOn.stream().filter(removed::contains).toList().forEach(ref -> SbomChecks.reachableFrom(ref, removedDependsOn, reached));
            dependsOn.addAll(reached);
            dependsOn.removeAll(removed);
        }
    }

    /**
     * The name Maven gives the file of a component, or null for a component whose file is not a Maven jar.
     */
    static String fileName(JsonNode component, Predicate<String> jarType) {
        PackageURL purl = SbomImage.parsePurl(component.path("purl").asText());
        if (purl == null || !PackageURL.StandardTypes.MAVEN.equals(purl.getType()) || purl.getVersion() == null) {
            return null;
        }
        Map<String, String> qualifiers = purl.getQualifiers() == null ? Map.of() : purl.getQualifiers();
        if (!jarType.test(qualifiers.getOrDefault("type", "jar"))) {
            return null;
        }
        return fileName(purl.getName(), purl.getVersion(), qualifiers.get("classifier"));
    }

    static String fileName(String artifactId, String version, String classifier) {
        return artifactId + "-" + version + (classifier == null || classifier.isEmpty() ? "" : "-" + classifier) + ".jar";
    }

    /**
     * A component for a Maven artifact whose file is a jar, with the purl and reference that cyclonedx-maven-plugin gives such an artifact.
     */
    static ObjectNode mavenComponent(String group, String artifactId, String version, String classifier, String type) {
        TreeMap<String, String> qualifiers = new TreeMap<>(Map.of("type", type));
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
     * A component for the declared library whose file is the packed one, {@code <name>-<version>.jar}. What follows the
     * name is taken for a version when it starts with a digit, or else when the library states it as its version: so a
     * declared name that is only the start of the name of another library does not match that library.
     *
     * @param statedVersion gives the version the packed library states about itself, or null when it states none
     */
    static Optional<ObjectNode> declared(List<PackedLibrary> libraries, String fileName, Supplier<String> statedVersion) {
        for (PackedLibrary declared : libraries) {
            String prefix = declared.getName() + "-";
            if (!fileName.startsWith(prefix) || !fileName.endsWith(".jar")) {
                continue;
            }
            String version = fileName.substring(prefix.length(), fileName.length() - ".jar".length());
            if (version.isEmpty() || !Character.isDigit(version.charAt(0)) && !version.equals(statedVersion.get())) {
                continue;
            }
            SbomChecks.check(declared.getGroup() != null && !declared.getGroup().isBlank(), "Library " + declared.getName() + " has no group");
            ObjectNode component = mavenComponent(declared.getGroup(), declared.getName(), version, null, "jar");
            SbomJson.putIfPresent(component, "description", declared.getDescription());
            SbomJson.putLicense(component, declared.getLicense());
            return Optional.of(component);
        }
        return Optional.empty();
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
