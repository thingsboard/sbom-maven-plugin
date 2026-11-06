package org.thingsboard.sbom;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

public final class SbomImage {

    private static final Pattern DIGEST = Pattern.compile("sha256:[0-9a-f]{64}");
    private static final Pattern REPOSITORY = Pattern.compile("[a-z0-9]+(?:[._-][a-z0-9]+)*/[a-z0-9]+(?:[._-][a-z0-9]+)*");
    private static final Set<String> OS_PACKAGE_TYPES = Set.of("deb", "rpm", "apk");
    private static final String LOCATION = "syft:location:0:path";
    private static final String PACKAGE_PATH = "cdx:npm:package:path";
    private static final String MANIFEST = "package.json";

    private SbomImage() {
    }

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
        BundledComponents.check(components, BundledComponents.Goal.IMAGE);
        SbomChecks.checkInput("OS", os);
        String specVersion = os.path("specVersion").asText();
        List<Bundled> included = components.stream()
                .map(component -> new Bundled(component, SbomPackage.resolve(component, specVersion)))
                .toList();

        String rootRef = image.purl();
        String osRootRef = SbomChecks.rootRef(os);
        Map<String, String> replaced = new HashMap<>();
        replaceOsPackages(os, included, replaced);
        claimScannedPackages(os, included, replaced);
        included.forEach(Bundled::dropNotInstalled);

        Map<String, String> osPurls = new HashMap<>();
        componentStream(os)
                .filter(osComponent -> !replaced.containsKey(osComponent.path("bom-ref").asText()))
                .forEach(osComponent -> osPurls.put(withoutQualifiers(osComponent.path("purl").asText()), osComponent.path("bom-ref").asText()));
        osPurls.remove("");
        Set<String> overlap = new LinkedHashSet<>();
        for (Bundled component : included) {
            if (component.dir() == null) {
                component.purls().stream().filter(osPurls::containsKey).forEach(overlap::add);
            }
        }
        check(overlap.isEmpty(), "The OS SBOM also lists components that come from the bundled SBOMs: " + overlap
                + "; exclude the directories the bundled packages install to from the OS scan");

        ObjectNode bom = JsonNodeFactory.instance.objectNode();
        bom.put("bomFormat", "CycloneDX");
        bom.put("specVersion", specVersion);
        bom.put("serialNumber", "urn:uuid:" + UUID.nameUUIDFromBytes(("image:" + rootRef).getBytes(StandardCharsets.UTF_8)));
        bom.put("version", 1);
        bom.set("metadata", metadata(os, included, image, rootRef));

        ArrayNode bomComponents = bom.putArray("components");
        Map<String, JsonNode> componentsByRef = new LinkedHashMap<>();
        componentStream(os)
                .filter(osComponent -> !replaced.containsKey(osComponent.path("bom-ref").asText()))
                .forEach(osComponent -> add(bomComponents, componentsByRef, osComponent, "the OS SBOM"));
        for (Bundled component : included) {
            add(bomComponents, componentsByRef, component.json(), "the bundled components");
            component.nested().forEach(nested -> add(bomComponents, componentsByRef, nested, "the SBOM of " + component.ref()));
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
        componentStream(os)
                .map(osComponent -> osComponent.path("bom-ref").asText())
                .filter(ref -> !replaced.containsKey(ref) && !osTargets.contains(ref))
                .forEach(rootDependsOn::add);
        for (Bundled component : included) {
            rootDependsOn.add(component.ref());
            component.dependencies().forEach((ref, targets) -> graph.computeIfAbsent(ref, key -> new LinkedHashSet<>()).addAll(targets));
        }
        Set<String> reachableFromRoot = SbomPackage.reachableFrom(rootRef, graph);
        for (String ref : osTargets) {
            if (componentsByRef.containsKey(ref) && !reachableFromRoot.contains(ref)) {
                rootDependsOn.add(ref);
                reachableFromRoot.addAll(SbomPackage.reachableFrom(ref, graph));
            }
        }
        componentsByRef.keySet().forEach(ref -> graph.computeIfAbsent(ref, key -> new LinkedHashSet<>()));
        ArrayNode dependencies = bom.putArray("dependencies");
        graph.forEach((ref, targets) -> {
            ObjectNode entry = dependencies.addObject().put("ref", ref);
            if (!targets.isEmpty()) {
                ArrayNode dependsOn = entry.putArray("dependsOn");
                targets.forEach(dependsOn::add);
            }
        });

        SbomChecks.checkInput("Image", bom);
        Set<String> reachable = SbomPackage.reachableFrom(rootRef, SbomPackage.dependencyGraph(bom));
        Set<String> unreachable = componentsByRef.keySet().stream()
                .filter(ref -> !reachable.contains(ref))
                .collect(Collectors.toCollection(LinkedHashSet::new));
        check(unreachable.isEmpty(), "Image SBOM components are not reachable from the image: " + unreachable);
        return bom;
    }

    private static void replaceOsPackages(JsonNode os, List<Bundled> included, Map<String, String> replaced) {
        for (Bundled component : included) {
            PackageURL purl = parsePurl(component.json().path("purl").asText());
            if (component.config().getFile() == null || purl == null || !OS_PACKAGE_TYPES.contains(purl.getType())) {
                continue;
            }
            List<JsonNode> matches = componentStream(os)
                    .filter(osComponent -> {
                        PackageURL scanned = parsePurl(osComponent.path("purl").asText());
                        return scanned != null && purl.getType().equals(scanned.getType()) && purl.getName().equals(scanned.getName());
                    })
                    .toList();
            check(matches.size() == 1, "The OS SBOM should list " + purl.getName() + " as one installed " + purl.getType() + " package, but lists it "
                    + matches.size() + " times; check that the image installs the package the SBOM was built for");
            String scannedVersion = parsePurl(matches.get(0).path("purl").asText()).getVersion();
            check(Objects.equals(purl.getVersion(), scannedVersion), "The image installs " + purl.getName() + " " + scannedVersion + ", but the SBOM of "
                    + component.ref() + " is for " + purl.getVersion() + "; check that the image installs the package the SBOM was built for");
            replaced.put(matches.get(0).path("bom-ref").asText(), component.ref());
        }
    }

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
                            owner.claim(location.substring(owner.dir().length() + 1), withoutQualifiers(osComponent.path("purl").asText()), location)));
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
        private final SbomPackage.Resolved resolved;
        private final Map<String, JsonNode> nestedByRef = new LinkedHashMap<>();
        private final Map<String, String> refByPath = new LinkedHashMap<>();
        private final Map<String, List<String>> pathsByRef = new LinkedHashMap<>();
        private final Map<String, Set<String>> installedAt = new LinkedHashMap<>();
        private final Set<String> dropped = new LinkedHashSet<>();

        Bundled(BundledComponent config, SbomPackage.Resolved resolved) {
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
            String ref = config.getBundleDir() != null ? listedRef(purl) : installedRef(packagePath(relative), purl, location);
            check(ref != null, "The image has " + purl + " at " + location + ", which the SBOM of " + ref() + " does not list");
            return ref;
        }

        private String installedRef(String path, String purl, String location) {
            String ref = refByPath.get(path);
            if (ref != null) {
                check(path.equals(".") || purl.equals(withoutQualifiers(nestedByRef.get(ref).path("purl").asText())),
                        "The image has " + purl + " at " + location + ", but the SBOM of " + ref() + " lists " + ref + " there");
            } else {
                ref = otherPlatformRef(purl);
            }
            if (ref != null) {
                installedAt.computeIfAbsent(ref, key -> new LinkedHashSet<>()).add(path);
            }
            return ref;
        }

        private String listedRef(String purl) {
            if (purl.equals(withoutQualifiers(json().path("purl").asText()))) {
                return ref();
            }
            return nestedByRef.entrySet().stream()
                    .filter(entry -> purl.equals(withoutQualifiers(entry.getValue().path("purl").asText())))
                    .map(Map.Entry::getKey)
                    .findFirst()
                    .orElse(null);
        }

        private String otherPlatformRef(String purl) {
            return nestedByRef.entrySet().stream()
                    .filter(entry -> optional(entry.getValue()) && !pathsByRef.containsKey(entry.getKey()))
                    .filter(entry -> purl.equals(withoutQualifiers(entry.getValue().path("purl").asText())))
                    .map(Map.Entry::getKey)
                    .findFirst()
                    .orElse(null);
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
            purls.add(withoutQualifiers(json().path("purl").asText()));
            nested().forEach(nested -> purls.add(withoutQualifiers(nested.path("purl").asText())));
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
        if (bundledMetadata.has("lifecycles")) {
            metadata.set("lifecycles", bundledMetadata.get("lifecycles").deepCopy());
        }
        if (os.path("metadata").has("tools")) {
            metadata.set("tools", os.path("metadata").get("tools").deepCopy());
        }
        int slash = image.repository().indexOf('/');
        ObjectNode root = metadata.putObject("component");
        root.put("type", "container");
        root.put("bom-ref", rootRef);
        if (bundledMetadata.path("component").has("manufacturer")) {
            root.set("manufacturer", bundledMetadata.path("component").get("manufacturer").deepCopy());
        }
        root.put("group", image.repository().substring(0, slash));
        root.put("name", image.repository().substring(slash + 1));
        root.put("version", image.tag());
        root.putArray("hashes").addObject().put("alg", "SHA-256").put("content", image.digest().substring("sha256:".length()));
        root.put("purl", rootRef);
        for (String field : List.of("manufacturer", "supplier")) {
            if (bundledMetadata.has(field)) {
                metadata.set(field, bundledMetadata.get(field).deepCopy());
            }
        }
        return metadata;
    }

    private static void add(ArrayNode bomComponents, Map<String, JsonNode> componentsByRef, JsonNode component, String source) {
        String ref = component.path("bom-ref").asText();
        JsonNode known = componentsByRef.get(ref);
        if (known == null) {
            bomComponents.add(component.deepCopy());
            componentsByRef.put(ref, component);
            return;
        }
        check(SbomPackage.sameComponent(known, component),
                "Component " + ref + " from " + source + " clashes with a different component that is already in the SBOM");
    }

    private static Stream<JsonNode> componentStream(JsonNode bom) {
        return StreamSupport.stream(bom.path("components").spliterator(), false);
    }

    private static String remap(String ref, Map<String, String> replaced) {
        return replaced.getOrDefault(ref, ref);
    }

    private static String withoutQualifiers(String purl) {
        int end = purl.length();
        for (char separator : new char[]{'?', '#'}) {
            int index = purl.indexOf(separator);
            if (index >= 0 && index < end) {
                end = index;
            }
        }
        return purl.substring(0, end);
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new SbomException(message);
        }
    }

}
