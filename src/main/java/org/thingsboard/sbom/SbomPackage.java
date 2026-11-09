// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
package org.thingsboard.sbom;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.thingsboard.sbom.BundledComponents.Resolved;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.thingsboard.sbom.SbomChecks.check;

public final class SbomPackage {

    private static final String SBOM_SUFFIX = ".cdx.json";

    private SbomPackage() {}

    public static List<Path> writeAll(Path applicationSbom, String name, String version, List<PackageFile> packages, List<BundledComponent> components) {
        List<PackageFile> included = packages.stream().filter(packageFile -> !packageFile.isSkip()).toList();
        if (included.isEmpty()) {
            return List.of();
        }
        JsonNode application = SbomFiles.readFile(applicationSbom);
        checkApplication(application, components);
        Map<BundledComponent, Resolved> resolved = new HashMap<>();
        Map<Path, ObjectNode> described = new LinkedHashMap<>();
        for (PackageFile packageFile : included) {
            described.put(outputFile(packageFile), describe(application, name, version, packageFile, components, resolved));
        }
        described.forEach(SbomFiles::writeFile);
        return List.copyOf(described.keySet());
    }

    public static void checkConfig(List<PackageFile> packages, List<BundledComponent> components) {
        check(packages != null && !packages.isEmpty(), "No packages configured");
        Set<String> ids = new LinkedHashSet<>();
        for (PackageFile packageFile : packages) {
            checkPackage(packageFile);
            check(ids.add(packageFile.getId()), "Package id " + packageFile.getId() + " is used more than once");
        }
        BundledComponents.validate(components, BundledComponents.Goal.PACKAGE);
        for (BundledComponent component : components) {
            for (String id : component.getPackages()) {
                check(ids.contains(id), "Bundled component " + component.ref() + " refers to unknown package " + id + "; known packages are " + ids);
            }
        }
    }

    public static ObjectNode describe(JsonNode application, String name, String version, PackageFile packageFile, List<BundledComponent> components) {
        checkApplication(application, components);
        return describe(application, name, version, packageFile, components, new HashMap<>());
    }

    private static Path outputFile(PackageFile packageFile) {
        Path file = packageFile.getFile().toPath();
        return file.resolveSibling(file.getFileName() + SBOM_SUFFIX);
    }

    private static void checkApplication(JsonNode application, List<BundledComponent> components) {
        SbomChecks.checkInput("Application", application);
        BundledComponents.validate(components, BundledComponents.Goal.PACKAGE);
    }

    private static void checkPackage(PackageFile packageFile) {
        check(packageFile.getId() != null && !packageFile.getId().isBlank(), "A package has no id");
        check(packageFile.getFile() != null, "Package " + packageFile.getId() + " has no file");
        SbomChecks.checkPurl("Package " + packageFile.getId(), packageFile.getPurl());
    }

    private static ObjectNode describe(JsonNode application, String name, String version, PackageFile packageFile, List<BundledComponent> components,
                                       Map<BundledComponent, Resolved> resolved) {
        checkPackage(packageFile);
        check(name != null && !name.isBlank(), "Package name is blank");
        check(version != null && !version.isBlank(), "Package version is blank");
        Path file = packageFile.getFile().toPath();
        check(Files.isRegularFile(file), "Package file " + file + " does not exist");
        check(size(file) > 0, "Package file " + file + " is empty");

        JsonNode applicationRoot = application.path("metadata").path("component");
        String applicationRef = applicationRoot.path("bom-ref").asText();
        String packageRef = packageFile.getPurl();
        String specVersion = application.path("specVersion").asText();
        List<Resolved> included = components.stream()
                .filter(component -> component.includedIn(packageFile.getId()))
                .map(component -> resolved.computeIfAbsent(component, key -> BundledComponents.resolve(key, specVersion)))
                .toList();
        Set<String> existingRefs = SbomChecks.componentRefs(application);
        existingRefs.add(applicationRef);
        check(!existingRefs.contains(packageRef), "Package purl " + packageRef + " is already used by a component of the application SBOM");
        Set<String> bundledRefs = new HashSet<>();
        for (Resolved component : included) {
            check(!existingRefs.contains(component.ref()) && !component.ref().equals(packageRef) && bundledRefs.add(component.ref()),
                    "Bundled component " + component.ref() + " clashes with a component that is already in the SBOM");
        }

        Map<String, String> packageHashes = SbomFiles.hashes(file);
        ObjectNode bom = SbomJson.newBom(specVersion, "package:" + packageRef + ":" + packageHashes.get("SHA-512"));
        bom.set("metadata", metadata(application.path("metadata"), packageRoot(applicationRoot, name, version, packageRef, packageHashes)));

        ArrayNode bomComponents = bom.putArray("components");
        Map<String, JsonNode> componentsByRef = new HashMap<>();
        bomComponents.add(applicationRoot.deepCopy());
        componentsByRef.put(applicationRef, applicationRoot);
        application.path("components").forEach(component -> {
            bomComponents.add(component.deepCopy());
            componentsByRef.put(component.path("bom-ref").asText(), component);
        });
        for (Resolved component : included) {
            bomComponents.add(component.json());
            componentsByRef.put(component.ref(), component.json());
        }
        for (Resolved component : included) {
            if (component.sbom() == null) {
                continue;
            }
            String source = "the SBOM of " + component.ref();
            for (JsonNode nested : component.sbom().path("components")) {
                String ref = nested.path("bom-ref").asText();
                check(!ref.equals(packageRef), "Component " + ref + " from " + source + " clashes with a different component that is already in the SBOM");
                SbomJson.addComponent(bomComponents, componentsByRef, nested, source);
            }
            SbomMerger.mergeTools(bom, component.sbom());
        }

        Map<String, Set<String>> graph = new LinkedHashMap<>();
        Set<String> rootDependsOn = graph.computeIfAbsent(packageRef, ref -> new LinkedHashSet<>());
        rootDependsOn.add(applicationRef);
        included.forEach(component -> rootDependsOn.add(component.ref()));
        SbomChecks.addDependencies(graph, application);
        graph.computeIfAbsent(applicationRef, ref -> new LinkedHashSet<>());
        for (Resolved component : included) {
            graph.computeIfAbsent(component.ref(), ref -> new LinkedHashSet<>());
            if (component.sbom() != null) {
                SbomChecks.addDependencies(graph, component.sbom());
            }
        }
        SbomJson.putDependencies(bom, graph);

        checkOutput(application, bom, packageRef, included, graph);
        return bom;
    }

    private static ObjectNode metadata(JsonNode applicationMetadata, ObjectNode root) {
        ObjectNode metadata = JsonNodeFactory.instance.objectNode();
        SbomJson.copyFields(applicationMetadata, metadata, "lifecycles", "tools");
        metadata.set("component", root);
        SbomJson.copyFields(applicationMetadata, metadata, "manufacturer", "supplier");
        return metadata;
    }

    private static ObjectNode packageRoot(JsonNode applicationRoot, String name, String version, String packageRef, Map<String, String> packageHashes) {
        ObjectNode root = JsonNodeFactory.instance.objectNode();
        root.put("type", "application");
        root.put("bom-ref", packageRef);
        SbomJson.copyFields(applicationRoot, root, "manufacturer");
        root.put("name", name);
        root.put("version", version);
        SbomJson.copyFields(applicationRoot, root, "description");
        root.set("hashes", SbomJson.hashesJson(packageHashes));
        SbomJson.copyFields(applicationRoot, root, "licenses");
        root.put("purl", packageRef);
        ArrayNode websites = JsonNodeFactory.instance.arrayNode();
        applicationRoot.path("externalReferences").forEach(reference -> {
            if ("website".equals(reference.path("type").asText())) {
                websites.add(reference.deepCopy());
            }
        });
        if (!websites.isEmpty()) {
            root.set("externalReferences", websites);
        }
        return root;
    }

    private static void checkOutput(JsonNode application, ObjectNode bom, String packageRef, List<Resolved> included, Map<String, Set<String>> graph) {
        SbomChecks.checkInput("Package", bom);
        check(SbomChecks.rootRef(bom).equals(packageRef), "Package SBOM root is not the package");
        Set<String> expected = new LinkedHashSet<>();
        expected.add(SbomChecks.rootRef(application));
        expected.addAll(SbomChecks.componentRefs(application));
        included.forEach(component -> expected.add(component.ref()));
        included.stream().filter(component -> component.sbom() != null).forEach(component -> expected.addAll(SbomChecks.componentRefs(component.sbom())));
        check(SbomChecks.componentRefs(bom).equals(expected), "Package SBOM components are not the application, its components and the bundled components");

        Set<String> packageReachable = SbomChecks.reachableFrom(packageRef, graph);
        Set<String> lost = SbomChecks.unreachable(SbomChecks.reachableFrom(SbomChecks.rootRef(application), SbomChecks.dependencyGraph(application)), packageReachable);
        check(lost.isEmpty(), "Package SBOM lost dependency paths to " + lost);
        for (Resolved component : included) {
            check(packageReachable.contains(component.ref()), "Bundled component " + component.ref() + " is not reachable from the package");
            if (component.sbom() != null) {
                Set<String> unreachable = SbomChecks.unreachable(SbomChecks.componentRefs(component.sbom()), packageReachable);
                check(unreachable.isEmpty(), "Components from the SBOM of " + component.ref() + " are not reachable from the package: " + unreachable);
            }
        }
    }

    private static long size(Path file) {
        try {
            return Files.size(file);
        } catch (IOException e) {
            throw new SbomException("Failed to read " + file, e);
        }
    }

}
