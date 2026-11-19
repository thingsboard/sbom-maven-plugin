// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
package org.thingsboard.sbom;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.thingsboard.sbom.SbomChecks.check;

public final class SbomPackage {

    private static final String SBOM_SUFFIX = ".cdx.json";

    private SbomPackage() {}

    public static List<Path> writeAll(Path applicationSbom, Path bundledDirectory, String name, String version, List<PackageFile> packages) {
        List<PackageFile> included = packages.stream().filter(packageFile -> !packageFile.isSkip()).toList();
        if (included.isEmpty()) {
            return List.of();
        }
        JsonNode application = SbomFiles.readFile(applicationSbom);
        SbomChecks.checkInput("Application", application);
        Map<Path, ObjectNode> described = new LinkedHashMap<>();
        for (PackageFile packageFile : included) {
            Path bundledFile = SbomBundled.file(bundledDirectory, name, packageFile.getId());
            check(Files.isRegularFile(bundledFile), "Package " + packageFile.getId() + " has no bundled SBOM " + bundledFile
                    + "; run the bundled goal before this one, with the same name and packages");
            described.put(outputFile(packageFile), describeChecked(application, name, version, packageFile, SbomFiles.readFile(bundledFile)));
        }
        described.forEach(SbomFiles::writeFile);
        return List.copyOf(described.keySet());
    }

    public static void checkConfig(List<PackageFile> packages) {
        PackageFile.checkIds(packages);
        packages.forEach(SbomPackage::checkPackage);
    }

    private static Path outputFile(PackageFile packageFile) {
        Path file = packageFile.getFile().toPath();
        return file.resolveSibling(file.getFileName() + SBOM_SUFFIX);
    }

    private static void checkPackage(PackageFile packageFile) {
        check(packageFile.getId() != null && !packageFile.getId().isBlank(), "A package has no id");
        check(packageFile.getFile() != null, "Package " + packageFile.getId() + " has no file");
        SbomChecks.checkPurl("Package " + packageFile.getId(), packageFile.getPurl());
    }

    /**
     * The SBOM of a package: the application SBOM and the bundled SBOM of the package, under the package as the root.
     */
    static ObjectNode describe(JsonNode application, String name, String version, PackageFile packageFile, JsonNode bundled) {
        SbomChecks.checkInput("Application", application);
        return describeChecked(application, name, version, packageFile, bundled);
    }

    private static ObjectNode describeChecked(JsonNode application, String name, String version, PackageFile packageFile, JsonNode bundled) {
        checkPackage(packageFile);
        PackageFile.checkNameAndVersion(name, version);
        Path file = packageFile.getFile().toPath();
        check(Files.isRegularFile(file), "Package file " + file + " does not exist");
        check(size(file) > 0, "Package file " + file + " is empty");

        String specVersion = application.path("specVersion").asText();
        String bundledSpecVersion = bundled.path("specVersion").asText();
        check(specVersion.equals(bundledSpecVersion),
                "Bundled SBOM of package " + packageFile.getId() + " is CycloneDX " + bundledSpecVersion + ", but the application SBOM is " + specVersion
                        + "; the package goal needs an application SBOM of CycloneDX " + bundledSpecVersion + ", which the bundled goal writes");
        SbomChecks.checkInput("Bundled", bundled);
        String bundledRoot = SbomChecks.rootRef(bundled);
        String expectedRoot = SbomBundled.rootRef(name, packageFile.getId(), version);
        check(bundledRoot.equals(expectedRoot), "Bundled SBOM of package " + packageFile.getId() + " is " + bundledRoot + ", not " + expectedRoot
                + "; run the bundled goal again, with the same name, version and packages");
        Map<String, Set<String>> bundledGraph = SbomChecks.dependencyGraph(bundled);
        Set<String> direct = bundledGraph.getOrDefault(bundledRoot, Set.of());

        JsonNode applicationRoot = application.path("metadata").path("component");
        String applicationRef = applicationRoot.path("bom-ref").asText();
        String packageRef = packageFile.getPurl();
        Set<String> existingRefs = SbomChecks.componentRefs(application);
        existingRefs.add(applicationRef);
        check(!existingRefs.contains(packageRef), "Package purl " + packageRef + " is already used by a component of the application SBOM");
        for (String ref : direct) {
            check(!existingRefs.contains(ref), "Bundled component " + ref + " clashes with a component that is already in the SBOM");
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
        String source = "the bundled SBOM of package " + packageFile.getId();
        for (JsonNode component : bundled.path("components")) {
            String ref = component.path("bom-ref").asText();
            check(!ref.equals(packageRef), "Component " + ref + " from " + source + " clashes with a different component that is already in the SBOM");
            SbomJson.addComponent(bomComponents, componentsByRef, component, source);
        }
        SbomMerger.mergeTools(bom, bundled);

        Map<String, Set<String>> graph = new LinkedHashMap<>();
        Set<String> rootDependsOn = graph.computeIfAbsent(packageRef, ref -> new LinkedHashSet<>());
        rootDependsOn.add(applicationRef);
        rootDependsOn.addAll(direct);
        SbomChecks.addDependencies(graph, application);
        graph.computeIfAbsent(applicationRef, ref -> new LinkedHashSet<>());
        bundledGraph.forEach((ref, targets) -> {
            if (!ref.equals(bundledRoot)) {
                graph.computeIfAbsent(ref, key -> new LinkedHashSet<>()).addAll(targets);
            }
        });
        SbomJson.putDependencies(bom, graph);

        checkOutput(application, bundled, bom, packageRef, graph);
        return bom;
    }

    private static ObjectNode metadata(JsonNode applicationMetadata, ObjectNode root) {
        ObjectNode metadata = JsonNodeFactory.instance.objectNode();
        SbomJson.copyFields(applicationMetadata, metadata, "timestamp", "lifecycles", "tools");
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

    private static void checkOutput(JsonNode application, JsonNode bundled, ObjectNode bom, String packageRef, Map<String, Set<String>> graph) {
        SbomChecks.checkInput("Package", bom);
        check(SbomChecks.rootRef(bom).equals(packageRef), "Package SBOM root is not the package");
        Set<String> expected = new LinkedHashSet<>();
        expected.add(SbomChecks.rootRef(application));
        expected.addAll(SbomChecks.componentRefs(application));
        expected.addAll(SbomChecks.componentRefs(bundled));
        check(SbomChecks.componentRefs(bom).equals(expected), "Package SBOM components are not the application, its components and the bundled components");

        Set<String> packageReachable = SbomChecks.reachableFrom(packageRef, graph);
        Set<String> lost = SbomChecks.unreachable(SbomChecks.reachableFrom(SbomChecks.rootRef(application), SbomChecks.dependencyGraph(application)), packageReachable);
        check(lost.isEmpty(), "Package SBOM lost dependency paths to " + lost);
        Set<String> unreachable = SbomChecks.unreachable(SbomChecks.componentRefs(bundled), packageReachable);
        check(unreachable.isEmpty(), "Bundled components are not reachable from the package: " + unreachable);
    }

    private static long size(Path file) {
        try {
            return Files.size(file);
        } catch (IOException e) {
            throw new SbomException("Failed to read " + file, e);
        }
    }

}
