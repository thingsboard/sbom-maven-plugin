// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
package org.thingsboard.sbom;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.thingsboard.sbom.BundledComponents.Resolved;

import java.nio.file.Path;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.thingsboard.sbom.SbomChecks.check;

/**
 * The SBOM of what a distribution package bundles besides the application: the components declared in the build, one SBOM
 * per package. It is written before the packages are built, so that what is made from it before them, such as the
 * third-party notices that go into the packages, can read it; the {@code package} goal adds it to the SBOM of the package.
 */
public final class SbomBundled {

    private static final String SUFFIX = ".bundled.cdx.json";

    private SbomBundled() {}

    /**
     * Where the bundled SBOM of a package is: {@code <directory>/<name>-<package id>.bundled.cdx.json}.
     */
    static Path file(Path directory, String name, String packageId) {
        return directory.resolve(name + "-" + packageId + SUFFIX);
    }

    /**
     * The root of the bundled SBOM of a package: the package checks it, so that a bundled SBOM of another package, or one
     * that an older build left, is not added.
     */
    static String rootRef(String name, String packageId, String version) {
        return name + "-" + packageId + "-bundled@" + version;
    }

    public static List<Path> writeAll(Path directory, String name, String version, List<PackageFile> packages, List<BundledComponent> components) {
        Map<BundledComponent, Resolved> resolved = new HashMap<>();
        Map<Path, ObjectNode> described = new LinkedHashMap<>();
        for (PackageFile packageFile : packages) {
            if (!packageFile.isSkip()) {
                described.put(file(directory, name, packageFile.getId()), describe(name, version, packageFile.getId(), components, resolved));
            }
        }
        described.forEach(SbomFiles::writeFile);
        return List.copyOf(described.keySet());
    }

    public static void checkConfig(List<PackageFile> packages, List<BundledComponent> components) {
        check(packages != null && !packages.isEmpty(), "No packages configured");
        Set<String> ids = new LinkedHashSet<>();
        for (PackageFile packageFile : packages) {
            check(packageFile.getId() != null && !packageFile.getId().isBlank(), "A package has no id");
            check(ids.add(packageFile.getId()), "Package id " + packageFile.getId() + " is used more than once");
        }
        BundledComponents.validate(components, BundledComponents.Goal.PACKAGE);
        for (BundledComponent component : components) {
            for (String id : component.getPackages()) {
                check(ids.contains(id), "Bundled component " + component.ref() + " refers to unknown package " + id + "; known packages are " + ids);
            }
        }
    }

    static ObjectNode describe(String name, String version, String packageId, List<BundledComponent> components) {
        BundledComponents.validate(components, BundledComponents.Goal.PACKAGE);
        return describe(name, version, packageId, components, new HashMap<>());
    }

    private static ObjectNode describe(String name, String version, String packageId, List<BundledComponent> components,
                                       Map<BundledComponent, Resolved> resolved) {
        check(name != null && !name.isBlank(), "Package name is blank");
        check(version != null && !version.isBlank(), "Package version is blank");
        String rootRef = rootRef(name, packageId, version);
        String specVersion = MavenComponents.SPEC_VERSION.getVersionString();
        List<Resolved> included = components.stream()
                .filter(component -> component.includedIn(packageId))
                .map(component -> resolved.computeIfAbsent(component, key -> BundledComponents.resolve(key, specVersion)))
                .toList();

        ArrayNode bomComponents = JsonNodeFactory.instance.arrayNode();
        Map<String, JsonNode> componentsByRef = new HashMap<>();
        for (Resolved component : included) {
            check(!component.ref().equals(rootRef) && !componentsByRef.containsKey(component.ref()),
                    "Bundled component " + component.ref() + " clashes with another bundled component");
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
                check(!ref.equals(rootRef), "Component " + ref + " from " + source + " clashes with a different component that is already in the SBOM");
                SbomJson.addComponent(bomComponents, componentsByRef, nested, source);
            }
        }

        ObjectNode bom = SbomJson.newBom(specVersion, "bundled:" + rootRef + ":" + bomComponents);
        ObjectNode metadata = bom.putObject("metadata");
        ObjectNode root = metadata.putObject("component");
        root.put("type", "application");
        root.put("bom-ref", rootRef);
        root.put("name", name + "-" + packageId + "-bundled");
        root.put("version", version);
        root.put("description", "What the " + packageId + " package of " + name + " bundles besides the application");
        bom.set("components", bomComponents);
        included.stream().filter(component -> component.sbom() != null).forEach(component -> SbomMerger.mergeTools(bom, component.sbom()));

        Map<String, Set<String>> graph = new LinkedHashMap<>();
        Set<String> rootDependsOn = graph.computeIfAbsent(rootRef, ref -> new LinkedHashSet<>());
        for (Resolved component : included) {
            rootDependsOn.add(component.ref());
            graph.computeIfAbsent(component.ref(), ref -> new LinkedHashSet<>());
            if (component.sbom() != null) {
                SbomChecks.addDependencies(graph, component.sbom());
            }
        }
        SbomJson.putDependencies(bom, graph);

        SbomChecks.checkInput("Bundled", bom);
        Set<String> unreachable = SbomChecks.unreachable(SbomChecks.componentRefs(bom), SbomChecks.reachableFrom(rootRef, graph));
        check(unreachable.isEmpty(), "Bundled SBOM of package " + packageId + " has components that are not reachable from its root: " + unreachable);
        return bom;
    }

}
