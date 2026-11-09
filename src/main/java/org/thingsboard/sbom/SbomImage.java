// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
package org.thingsboard.sbom;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import static org.thingsboard.sbom.SbomChecks.check;

public final class SbomImage {

    private static final Pattern DIGEST = Pattern.compile("sha256:[0-9a-f]{64}");
    private static final Pattern REPOSITORY = Pattern.compile("[a-z0-9]+(?:[._-][a-z0-9]+)*/[a-z0-9]+(?:[._-][a-z0-9]+)*");
    private static final Set<String> OS_PACKAGE_TYPES = Set.of("deb", "rpm", "apk");
    private static final String LOCATION = "syft:location:0:path";
    private static final String PACKAGE_PATH = "cdx:npm:package:path";
    private static final String MANIFEST = "package.json";

    private SbomImage() {}

    public record Image(String repository, String tag, String digest, String architecture) {

        String purl() {
            return "pkg:docker/" + repository + "@" + digest.replace(":", "%3A") + "?arch=" + architecture;
        }

    }

    public static void write(Path osSbom, Image image, List<BundledComponent> components, Path output) {
        SbomFiles.writeFile(output, describe(SbomFiles.readFile(osSbom), image, components));
    }

    public static ObjectNode describe(JsonNode os, Image image, List<BundledComponent> components) {
        checkImage(image);
        check(components != null && !components.isEmpty(), "No bundled components configured: the image SBOM needs the SBOM of what the image installs");
        BundledComponents.validate(components, BundledComponents.Goal.IMAGE);
        SbomChecks.checkInput("OS", os);
        String specVersion = os.path("specVersion").asText();
        List<Bundled> included = components.stream()
                .map(component -> new Bundled(component, BundledComponents.resolve(component, specVersion)))
                .toList();

        String rootRef = image.purl();
        String osRootRef = SbomChecks.rootRef(os);
        Map<String, String> replaced = new HashMap<>();
        replaceOsPackages(os, included, replaced);
        claimScannedPackages(os, included, replaced);
        included.forEach(Bundled::dropNotInstalled);

        List<JsonNode> keptOs = componentStream(os).filter(osComponent -> !replaced.containsKey(osComponent.path("bom-ref").asText())).toList();
        Set<String> osPurls = keptOs.stream().map(SbomImage::purlOf).filter(purl -> !purl.isEmpty()).collect(Collectors.toSet());
        Set<String> overlap = new LinkedHashSet<>();
        for (Bundled component : included) {
            if (component.dir() == null) {
                component.purls().stream().filter(osPurls::contains).forEach(overlap::add);
            }
        }
        check(overlap.isEmpty(), "The OS SBOM also lists components that come from the bundled SBOMs: " + overlap
                + "; exclude the directories the bundled packages install to from the OS scan");

        ObjectNode bom = SbomJson.newBom(specVersion, "image:" + rootRef);
        bom.set("metadata", metadata(os, included, image, rootRef));

        ArrayNode bomComponents = bom.putArray("components");
        Map<String, JsonNode> componentsByRef = new LinkedHashMap<>();
        keptOs.forEach(osComponent -> SbomJson.addComponent(bomComponents, componentsByRef, osComponent, "the OS SBOM"));
        for (Bundled component : included) {
            SbomJson.addComponent(bomComponents, componentsByRef, component.json(), "the bundled components");
            component.nested().forEach(nested -> SbomJson.addComponent(bomComponents, componentsByRef, nested, "the SBOM of " + component.ref()));
            if (component.sbom() != null) {
                SbomMerger.mergeTools(bom, component.sbom());
            }
        }

        Map<String, Set<String>> graph = new LinkedHashMap<>();
        Set<String> osTargets = new LinkedHashSet<>();
        for (JsonNode dependency : os.path("dependencies")) {
            String ref = remap(dependency.path("ref").asText(), replaced);
            if (ref.equals(osRootRef)) {
                continue;
            }
            Set<String> targets = graph.computeIfAbsent(ref, key -> new LinkedHashSet<>());
            dependency.path("dependsOn").forEach(target -> {
                String mapped = remap(target.asText(), replaced);
                if (!mapped.equals(ref)) {
                    targets.add(mapped);
                    osTargets.add(mapped);
                }
            });
        }
        Set<String> rootDependsOn = graph.computeIfAbsent(rootRef, key -> new LinkedHashSet<>());
        keptOs.stream()
                .map(osComponent -> osComponent.path("bom-ref").asText())
                .filter(ref -> !osTargets.contains(ref))
                .forEach(rootDependsOn::add);
        for (Bundled component : included) {
            rootDependsOn.add(component.ref());
            component.dependencies().forEach((ref, targets) -> graph.computeIfAbsent(ref, key -> new LinkedHashSet<>()).addAll(targets));
        }
        Set<String> reachable = SbomChecks.reachableFrom(rootRef, graph);
        List<String> orphaned = osTargets.stream().filter(ref -> componentsByRef.containsKey(ref) && !reachable.contains(ref)).toList();
        for (String ref : cycleEntries(orphaned, graph)) {
            rootDependsOn.add(ref);
            SbomChecks.reachableFrom(ref, graph, reachable);
        }
        componentsByRef.keySet().forEach(ref -> graph.computeIfAbsent(ref, key -> new LinkedHashSet<>()));
        SbomJson.putDependencies(bom, graph);

        SbomChecks.checkInput("Image", bom);
        Set<String> unreachable = SbomChecks.unreachable(componentsByRef.keySet(), reachable);
        check(unreachable.isEmpty(), "Image SBOM components are not reachable from the image: " + unreachable);
        return bom;
    }

    private static List<String> cycleEntries(List<String> orphaned, Map<String, Set<String>> graph) {
        Map<String, Set<String>> reaches = new HashMap<>();
        orphaned.forEach(ref -> reaches.put(ref, SbomChecks.reachableFrom(ref, graph)));
        Set<String> covered = new HashSet<>();
        List<String> entries = new ArrayList<>();
        for (String ref : orphaned) {
            boolean source = orphaned.stream().noneMatch(other -> reaches.get(other).contains(ref) && !reaches.get(ref).contains(other));
            if (source && !covered.contains(ref)) {
                entries.add(ref);
                covered.addAll(reaches.get(ref));
            }
        }
        return entries;
    }

    private static void replaceOsPackages(JsonNode os, List<Bundled> included, Map<String, String> replaced) {
        Map<String, List<ScannedPackage>> scannedByName = null;
        for (Bundled component : included) {
            PackageURL purl = parsePurl(component.json().path("purl").asText());
            if (component.config().getFile() == null || purl == null || !OS_PACKAGE_TYPES.contains(purl.getType())) {
                continue;
            }
            if (scannedByName == null) {
                scannedByName = componentStream(os)
                        .map(osComponent -> new ScannedPackage(osComponent.path("bom-ref").asText(), parsePurl(osComponent.path("purl").asText())))
                        .filter(scanned -> scanned.purl() != null)
                        .collect(Collectors.groupingBy(scanned -> scanned.purl().getType() + "/" + scanned.purl().getName()));
            }
            List<ScannedPackage> matches = scannedByName.getOrDefault(purl.getType() + "/" + purl.getName(), List.of());
            check(matches.size() == 1, "The OS SBOM should list " + purl.getName() + " as one installed " + purl.getType() + " package, but lists it "
                    + matches.size() + " times; check that the image installs the package the SBOM was built for");
            String scannedVersion = matches.get(0).purl().getVersion();
            check(Objects.equals(purl.getVersion(), scannedVersion), "The image installs " + purl.getName() + " " + scannedVersion + ", but the SBOM of "
                    + component.ref() + " is for " + purl.getVersion() + "; check that the image installs the package the SBOM was built for");
            replaced.put(matches.get(0).ref(), component.ref());
        }
    }

    private record ScannedPackage(String ref, PackageURL purl) {}

    private static PackageURL parsePurl(String purl) {
        try {
            return purl.isEmpty() ? null : new PackageURL(purl);
        } catch (MalformedPackageURLException e) {
            return null;
        }
    }

    private static void claimScannedPackages(JsonNode os, List<Bundled> included, Map<String, String> replaced) {
        List<Bundled> located = included.stream().filter(component -> component.dir() != null).toList();
        if (located.isEmpty()) {
            return;
        }
        componentStream(os).forEach(osComponent -> {
            String location = location(osComponent);
            located.stream()
                    .filter(component -> location.startsWith(component.dir() + "/"))
                    .max(Comparator.comparingInt(component -> component.dir().length()))
                    .ifPresent(owner -> replaced.put(osComponent.path("bom-ref").asText(),
                            owner.claim(location.substring(owner.dir().length() + 1), purlOf(osComponent), location)));
        });
    }

    private static String location(JsonNode component) {
        for (JsonNode property : component.path("properties")) {
            if (LOCATION.equals(property.path("name").asText())) {
                return property.path("value").asText();
            }
        }
        return "";
    }

    private static final class Bundled {

        private final BundledComponent config;
        private final BundledComponents.Resolved resolved;
        private final Map<String, JsonNode> nestedByRef = new LinkedHashMap<>();
        private final Map<String, String> refByPath = new LinkedHashMap<>();
        private final Map<String, List<String>> pathsByRef = new LinkedHashMap<>();
        private final Map<String, String> refByPurl = new HashMap<>();
        private final Map<String, String> otherPlatformRefByPurl = new HashMap<>();
        private final Map<String, Set<String>> installedAt = new LinkedHashMap<>();
        private final Set<String> dropped = new LinkedHashSet<>();

        Bundled(BundledComponent config, BundledComponents.Resolved resolved) {
            this.config = config;
            this.resolved = resolved;
            if (resolved.sbom() != null) {
                componentStream(resolved.sbom()).forEach(nested -> nestedByRef.put(nested.path("bom-ref").asText(), nested));
            }
            if (config.getInstallDir() != null) {
                refByPath.put(".", resolved.ref());
                nestedByRef.forEach((ref, nested) -> nested.path("properties").forEach(property -> {
                    if (PACKAGE_PATH.equals(property.path("name").asText())) {
                        refByPath.put(property.path("value").asText(), ref);
                        pathsByRef.computeIfAbsent(ref, key -> new ArrayList<>()).add(property.path("value").asText());
                    }
                }));
                nestedByRef.forEach((ref, nested) -> {
                    if (optional(nested) && !pathsByRef.containsKey(ref)) {
                        putPurl(otherPlatformRefByPurl, nested, ref);
                    }
                });
            }
            putPurl(refByPurl, resolved.json(), resolved.ref());
            nestedByRef.forEach((ref, nested) -> putPurl(refByPurl, nested, ref));
        }

        private static void putPurl(Map<String, String> refs, JsonNode component, String ref) {
            String purl = purlOf(component);
            if (!purl.isEmpty()) {
                refs.putIfAbsent(purl, ref);
            }
        }

        BundledComponent config() {
            return config;
        }

        String ref() {
            return resolved.ref();
        }

        ObjectNode json() {
            return resolved.json();
        }

        JsonNode sbom() {
            return resolved.sbom();
        }

        String dir() {
            return config.getInstallDir() != null ? config.getInstallDir() : config.getBundleDir();
        }

        String claim(String relative, String purl, String location) {
            check(!purl.isEmpty(), "The image has a component without a purl at " + location + ", so it cannot be checked against the SBOM of " + ref());
            String ref = config.getBundleDir() != null ? refByPurl.get(purl) : installedRef(packagePath(relative), purl, location);
            check(ref != null, "The image has " + purl + " at " + location + ", which the SBOM of " + ref() + " does not list");
            return ref;
        }

        private String installedRef(String path, String purl, String location) {
            String ref = refByPath.get(path);
            if (ref != null) {
                check(path.equals(".") || purl.equals(purlOf(nestedByRef.get(ref))),
                        "The image has " + purl + " at " + location + ", but the SBOM of " + ref() + " lists " + ref + " there");
            } else {
                ref = otherPlatformRefByPurl.get(purl);
            }
            if (ref != null) {
                installedAt.computeIfAbsent(ref, key -> new LinkedHashSet<>()).add(path);
            }
            return ref;
        }

        private static String packagePath(String relative) {
            if (relative.equals(MANIFEST)) {
                return ".";
            }
            return relative.endsWith("/" + MANIFEST) ? relative.substring(0, relative.length() - MANIFEST.length() - 1) : relative;
        }

        void dropNotInstalled() {
            if (config.getInstallDir() == null) {
                return;
            }
            nestedByRef.forEach((ref, nested) -> {
                Set<String> installed = installedAt.getOrDefault(ref, Set.of());
                if (optional(nested)) {
                    if (installed.isEmpty()) {
                        dropped.add(ref);
                    }
                    return;
                }
                List<String> paths = pathsByRef.getOrDefault(ref, List.of());
                check(!paths.isEmpty(), "The SBOM of " + ref() + " lists " + ref + " without the path it is installed at, so the image cannot be checked for it");
                List<String> missing = paths.stream().filter(path -> !installed.contains(path)).map(path -> config.getInstallDir() + "/" + path).toList();
                check(missing.isEmpty(), "The SBOM of " + ref() + " lists " + ref + " at " + missing + ", but the image does not have it there");
            });
        }

        private static boolean optional(JsonNode component) {
            return "optional".equals(component.path("scope").asText());
        }

        List<JsonNode> nested() {
            return nestedByRef.entrySet().stream().filter(entry -> !dropped.contains(entry.getKey())).map(Map.Entry::getValue).toList();
        }

        Map<String, Set<String>> dependencies() {
            Map<String, Set<String>> result = new LinkedHashMap<>();
            if (sbom() == null) {
                return result;
            }
            for (JsonNode dependency : sbom().path("dependencies")) {
                String ref = dependency.path("ref").asText();
                if (dropped.contains(ref)) {
                    continue;
                }
                Set<String> targets = result.computeIfAbsent(ref, key -> new LinkedHashSet<>());
                dependency.path("dependsOn").forEach(target -> {
                    if (!dropped.contains(target.asText())) {
                        targets.add(target.asText());
                    }
                });
            }
            return result;
        }

        Set<String> purls() {
            Set<String> purls = new LinkedHashSet<>();
            purls.add(purlOf(json()));
            nested().forEach(nested -> purls.add(purlOf(nested)));
            purls.remove("");
            return purls;
        }

    }

    private static void checkImage(Image image) {
        check(image != null, "No image configured");
        check(image.repository() != null && REPOSITORY.matcher(image.repository()).matches(),
                "Image repository " + image.repository() + " must be <namespace>/<name>, for example thingsboard/tb-node");
        check(image.tag() != null && !image.tag().isBlank(), "Image tag is blank");
        check(image.digest() != null && DIGEST.matcher(image.digest()).matches(),
                "Image digest " + image.digest() + " must be sha256:<64 hex digits> of one architecture's image manifest");
        check(image.architecture() != null && !image.architecture().isBlank(), "Image architecture is blank");
    }

    private static ObjectNode metadata(JsonNode os, List<Bundled> included, Image image, String rootRef) {
        ObjectNode metadata = JsonNodeFactory.instance.objectNode();
        JsonNode bundledMetadata = included.stream()
                .map(Bundled::sbom)
                .filter(Objects::nonNull)
                .findFirst()
                .map(sbom -> sbom.path("metadata"))
                .orElse(JsonNodeFactory.instance.objectNode());
        SbomJson.copyFields(bundledMetadata, metadata, "lifecycles");
        SbomJson.copyFields(os.path("metadata"), metadata, "tools");
        int slash = image.repository().indexOf('/');
        ObjectNode root = metadata.putObject("component");
        root.put("type", "container");
        root.put("bom-ref", rootRef);
        SbomJson.copyFields(bundledMetadata.path("component"), root, "manufacturer");
        root.put("group", image.repository().substring(0, slash));
        root.put("name", image.repository().substring(slash + 1));
        root.put("version", image.tag());
        root.set("hashes", SbomJson.hashesJson(Map.of("SHA-256", image.digest().substring("sha256:".length()))));
        root.put("purl", rootRef);
        SbomJson.copyFields(bundledMetadata, metadata, "manufacturer", "supplier");
        return metadata;
    }

    private static Stream<JsonNode> componentStream(JsonNode bom) {
        return StreamSupport.stream(bom.path("components").spliterator(), false);
    }

    private static String remap(String ref, Map<String, String> replaced) {
        return replaced.getOrDefault(ref, ref);
    }

    private static String purlOf(JsonNode component) {
        return component.path("purl").asText().split("[?#]", 2)[0];
    }

}
