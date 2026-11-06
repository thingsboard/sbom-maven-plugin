package org.thingsboard.sbom;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public final class SbomPackage {

    private static final String SBOM_SUFFIX = ".cdx.json";
    private static final List<String> HASH_ALGORITHMS = List.of("SHA-256", "SHA-512");

    private SbomPackage() {
    }

    public static Path outputFile(PackageFile packageFile) {
        Path file = packageFile.getFile().toPath();
        return file.resolveSibling(file.getFileName() + SBOM_SUFFIX);
    }

    public static Path writeFor(Path applicationSbom, String name, String version, PackageFile packageFile, List<BundledComponent> components) {
        JsonNode application = SbomFiles.readFile(applicationSbom);
        ObjectNode described = describe(application, name, version, packageFile, components);
        Path output = outputFile(packageFile);
        SbomFiles.writeFile(output, described);
        return output;
    }

    public static void checkConfig(List<PackageFile> packages, List<BundledComponent> components) {
        check(packages != null && !packages.isEmpty(), "No packages configured");
        Set<String> ids = new LinkedHashSet<>();
        for (PackageFile packageFile : packages) {
            checkPackage(packageFile);
            check(ids.add(packageFile.getId()), "Package id " + packageFile.getId() + " is used more than once");
        }
        checkComponents(components);
        for (BundledComponent component : components) {
            for (String id : component.getPackages()) {
                check(ids.contains(id), "Bundled component " + component.ref() + " refers to unknown package " + id + "; known packages are " + ids);
            }
        }
    }

    private static void checkPackage(PackageFile packageFile) {
        check(packageFile.getId() != null && !packageFile.getId().isBlank(), "A package has no id");
        check(packageFile.getFile() != null, "Package " + packageFile.getId() + " has no file");
        checkPurl("Package " + packageFile.getId(), packageFile.getPurl());
    }

    private static void checkComponents(List<BundledComponent> components) {
        Set<String> refs = new HashSet<>();
        for (BundledComponent component : components) {
            if (component.getSbom() == null) {
                check(component.getName() != null && !component.getName().isBlank(), "A bundled component has no name");
            } else {
                checkSbomComponent(component);
            }
            check(component.getInstallDir() == null && component.getBundleDir() == null,
                    "Bundled component " + component.ref() + " sets installDir or bundleDir, which only apply to image SBOMs");
            check(refs.add(component.ref()), "Bundled component " + component.ref() + " is declared more than once");
        }
    }

    private static void checkSbomComponent(BundledComponent component) {
        Map<String, String> details = new LinkedHashMap<>();
        details.put("group", component.getGroup());
        details.put("name", component.getName());
        details.put("version", component.getVersion());
        details.put("description", component.getDescription());
        details.put("purl", component.getPurl());
        details.put("cpe", component.getCpe());
        details.put("license", component.getLicense());
        List<String> set = new ArrayList<>(details.entrySet().stream()
                .filter(entry -> entry.getValue() != null && !entry.getValue().isBlank())
                .map(Map.Entry::getKey)
                .toList());
        if (component.getSupplier() != null) {
            set.add("supplier");
        }
        check(set.isEmpty(), "Bundled component " + component.ref() + " takes its details from its SBOM and must not set " + set);
        check(component.getFile() != null, "Bundled component " + component.ref() + " has an SBOM but no file to check it against");
    }

    public static ObjectNode describe(JsonNode application, String name, String version, PackageFile packageFile, List<BundledComponent> components) {
        SbomChecks.checkInput("Application", application);
        checkPackage(packageFile);
        checkComponents(components);
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
                .map(component -> resolve(component, specVersion))
                .toList();
        Set<String> existingRefs = SbomChecks.componentRefs(application);
        existingRefs.add(applicationRef);
        check(!existingRefs.contains(packageRef), "Package purl " + packageRef + " is already used by a component of the application SBOM");
        Set<String> bundledRefs = new HashSet<>();
        for (Resolved component : included) {
            check(!existingRefs.contains(component.ref()) && !component.ref().equals(packageRef) && bundledRefs.add(component.ref()),
                    "Bundled component " + component.ref() + " clashes with a component that is already in the SBOM");
        }

        Map<String, String> packageHashes = hashes(file);
        ObjectNode bom = JsonNodeFactory.instance.objectNode();
        bom.put("bomFormat", "CycloneDX");
        bom.put("specVersion", specVersion);
        bom.put("serialNumber", "urn:uuid:" + UUID.nameUUIDFromBytes(("package:" + packageRef + ":" + packageHashes.get("SHA-512")).getBytes(StandardCharsets.UTF_8)));
        bom.put("version", 1);
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
            for (JsonNode nested : component.sbom().path("components")) {
                String ref = nested.path("bom-ref").asText();
                JsonNode known = componentsByRef.get(ref);
                if (known == null && !ref.equals(packageRef)) {
                    bomComponents.add(nested.deepCopy());
                    componentsByRef.put(ref, nested);
                } else {
                    check(known != null && !nested.path("purl").asText().isEmpty() && known.path("purl").asText().equals(nested.path("purl").asText()),
                            "Component " + ref + " from the SBOM of " + component.ref() + " clashes with a different component that is already in the SBOM");
                }
            }
            SbomMerger.mergeTools(bom, component.sbom());
        }

        Map<String, Set<String>> graph = new LinkedHashMap<>();
        Set<String> rootDependsOn = graph.computeIfAbsent(packageRef, ref -> new LinkedHashSet<>());
        rootDependsOn.add(applicationRef);
        included.forEach(component -> rootDependsOn.add(component.ref()));
        addDependencies(graph, application);
        graph.computeIfAbsent(applicationRef, ref -> new LinkedHashSet<>());
        for (Resolved component : included) {
            graph.computeIfAbsent(component.ref(), ref -> new LinkedHashSet<>());
            if (component.sbom() != null) {
                addDependencies(graph, component.sbom());
            }
        }
        ArrayNode dependencies = bom.putArray("dependencies");
        graph.forEach((ref, targets) -> {
            ObjectNode entry = dependencies.addObject().put("ref", ref);
            if (!targets.isEmpty()) {
                ArrayNode dependsOn = entry.putArray("dependsOn");
                targets.forEach(dependsOn::add);
            }
        });

        checkOutput(application, bom, packageRef, included);
        return bom;
    }

    private static void addDependencies(Map<String, Set<String>> graph, JsonNode bom) {
        for (JsonNode dependency : bom.path("dependencies")) {
            Set<String> targets = graph.computeIfAbsent(dependency.path("ref").asText(), ref -> new LinkedHashSet<>());
            dependency.path("dependsOn").forEach(target -> targets.add(target.asText()));
        }
    }

    static Resolved resolve(BundledComponent component, String specVersion) {
        if (component.getSbom() == null) {
            return new Resolved(component.ref(), toJson(component), null);
        }
        Path sbomFile = component.getSbom().toPath();
        String label = "Bundled component SBOM " + sbomFile;
        JsonNode nested = SbomFiles.readFile(sbomFile);
        SbomChecks.checkInput(label, nested);
        check(specVersion.equals(nested.path("specVersion").asText()),
                label + " is CycloneDX " + nested.path("specVersion").asText() + ", but the SBOM it goes into is " + specVersion);
        ObjectNode root = (ObjectNode) nested.path("metadata").path("component").deepCopy();
        String ref = root.path("bom-ref").asText();
        if (component.getFile() != null) {
            Path file = component.getFile().toPath();
            check(Files.isRegularFile(file), "Bundled component " + ref + " points to " + file + ", which does not exist");
            Map<String, String> declared = new HashMap<>();
            root.path("hashes").forEach(hash -> declared.put(hash.path("alg").asText(), hash.path("content").asText().toLowerCase(Locale.ROOT)));
            check(declared.containsKey("SHA-256"), label + " does not give the SHA-256 of " + ref);
            Map<String, String> actual = hashes(file);
            actual.forEach((alg, content) -> check(!declared.containsKey(alg) || declared.get(alg).equals(content),
                    label + " was built for a file with " + alg + " " + declared.get(alg) + ", but " + file + " has " + content
                            + "; copy the SBOM that was built together with this file"));
            root.set("hashes", hashesJson(actual));
        }
        Set<String> reachable = reachableFrom(ref, dependencyGraph(nested));
        Set<String> unreachable = SbomChecks.componentRefs(nested).stream()
                .filter(nestedRef -> !reachable.contains(nestedRef))
                .collect(Collectors.toCollection(LinkedHashSet::new));
        check(unreachable.isEmpty(), label + " has components that its root does not depend on: " + unreachable);
        return new Resolved(ref, root, nested);
    }

    record Resolved(String ref, ObjectNode json, JsonNode sbom) {
    }

    private static ObjectNode metadata(JsonNode applicationMetadata, ObjectNode root) {
        ObjectNode metadata = JsonNodeFactory.instance.objectNode();
        for (String field : List.of("lifecycles", "tools")) {
            if (applicationMetadata.has(field)) {
                metadata.set(field, applicationMetadata.get(field).deepCopy());
            }
        }
        metadata.set("component", root);
        for (String field : List.of("manufacturer", "supplier")) {
            if (applicationMetadata.has(field)) {
                metadata.set(field, applicationMetadata.get(field).deepCopy());
            }
        }
        return metadata;
    }

    private static ObjectNode packageRoot(JsonNode applicationRoot, String name, String version, String packageRef, Map<String, String> packageHashes) {
        ObjectNode root = JsonNodeFactory.instance.objectNode();
        root.put("type", "application");
        root.put("bom-ref", packageRef);
        if (applicationRoot.has("manufacturer")) {
            root.set("manufacturer", applicationRoot.get("manufacturer").deepCopy());
        }
        root.put("name", name);
        root.put("version", version);
        if (applicationRoot.has("description")) {
            root.set("description", applicationRoot.get("description").deepCopy());
        }
        root.set("hashes", hashesJson(packageHashes));
        if (applicationRoot.has("licenses")) {
            root.set("licenses", applicationRoot.get("licenses").deepCopy());
        }
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

    private static ObjectNode toJson(BundledComponent component) {
        ObjectNode json = JsonNodeFactory.instance.objectNode();
        json.put("type", component.getType() == null || component.getType().isBlank() ? "library" : component.getType());
        json.put("bom-ref", component.ref());
        if (component.getSupplier() != null) {
            json.set("supplier", organization(component));
        }
        putIfPresent(json, "group", component.getGroup());
        json.put("name", component.getName());
        putIfPresent(json, "version", component.getVersion());
        putIfPresent(json, "description", component.getDescription());
        if (component.getFile() != null) {
            Path file = component.getFile().toPath();
            if (Files.isDirectory(file)) {
                check(!isEmptyDirectory(file), "Bundled component " + component.ref() + " points to an empty directory " + file);
            } else {
                check(Files.isRegularFile(file), "Bundled component " + component.ref() + " points to " + file + ", which does not exist");
                json.set("hashes", hashesJson(hashes(file)));
            }
        }
        if (component.getLicense() != null && !component.getLicense().isBlank()) {
            json.putArray("licenses").addObject().put("expression", component.getLicense());
        }
        if (component.getPurl() != null && !component.getPurl().isBlank()) {
            checkPurl("Bundled component " + component.getName(), component.getPurl());
            json.put("purl", component.getPurl());
        }
        if (component.getCpe() != null && !component.getCpe().isBlank()) {
            check(component.getCpe().startsWith("cpe:2.3:") || component.getCpe().startsWith("cpe:/"),
                    "Bundled component " + component.ref() + " has an invalid cpe " + component.getCpe());
            json.put("cpe", component.getCpe());
        }
        if ("cryptographic-asset".equals(json.path("type").asText())) {
            check(component.getFile() != null && Files.isRegularFile(component.getFile().toPath()),
                    "Bundled component " + component.ref() + " is a cryptographic-asset and needs a certificate file");
            json.set("cryptoProperties", certificateProperties(component.ref(), component.getFile().toPath()));
        }
        return json;
    }

    private static ObjectNode organization(BundledComponent component) {
        Organization supplier = component.getSupplier();
        check(supplier.getName() != null && !supplier.getName().isBlank(), "Bundled component " + component.ref() + " has a supplier without name");
        ObjectNode json = JsonNodeFactory.instance.objectNode().put("name", supplier.getName());
        if (!supplier.getUrls().isEmpty()) {
            ArrayNode urls = json.putArray("url");
            supplier.getUrls().forEach(urls::add);
        }
        return json;
    }

    private static ObjectNode certificateProperties(String ref, Path file) {
        X509Certificate certificate;
        try (InputStream in = Files.newInputStream(file)) {
            certificate = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
        } catch (IOException | CertificateException | ClassCastException e) {
            throw new SbomException("Bundled component " + ref + " points to " + file + ", which is not an X.509 certificate", e);
        }
        ObjectNode crypto = JsonNodeFactory.instance.objectNode().put("assetType", "certificate");
        ObjectNode properties = crypto.putObject("certificateProperties");
        properties.put("subjectName", certificate.getSubjectX500Principal().getName());
        properties.put("issuerName", certificate.getIssuerX500Principal().getName());
        properties.put("notValidBefore", certificate.getNotBefore().toInstant().toString());
        properties.put("notValidAfter", certificate.getNotAfter().toInstant().toString());
        properties.put("certificateFormat", "X.509");
        String fileName = file.getFileName().toString();
        int dot = fileName.lastIndexOf('.');
        if (dot >= 0 && dot < fileName.length() - 1) {
            properties.put("certificateExtension", fileName.substring(dot + 1));
        }
        return crypto;
    }

    private static void checkOutput(JsonNode application, ObjectNode bom, String packageRef, List<Resolved> included) {
        SbomChecks.checkInput("Package", bom);
        check(SbomChecks.rootRef(bom).equals(packageRef), "Package SBOM root is not the package");
        Set<String> expected = new LinkedHashSet<>();
        expected.add(SbomChecks.rootRef(application));
        expected.addAll(SbomChecks.componentRefs(application));
        included.forEach(component -> expected.add(component.ref()));
        included.stream().filter(component -> component.sbom() != null).forEach(component -> expected.addAll(SbomChecks.componentRefs(component.sbom())));
        check(SbomChecks.componentRefs(bom).equals(expected), "Package SBOM components are not the application, its components and the bundled components");

        Set<String> applicationReachable = reachableFrom(SbomChecks.rootRef(application), dependencyGraph(application));
        Set<String> packageReachable = reachableFrom(packageRef, dependencyGraph(bom));
        Set<String> lost = applicationReachable.stream().filter(ref -> !packageReachable.contains(ref)).collect(Collectors.toCollection(LinkedHashSet::new));
        check(lost.isEmpty(), "Package SBOM lost dependency paths to " + lost);
        for (Resolved component : included) {
            check(packageReachable.contains(component.ref()), "Bundled component " + component.ref() + " is not reachable from the package");
            if (component.sbom() != null) {
                Set<String> unreachable = SbomChecks.componentRefs(component.sbom()).stream()
                        .filter(ref -> !packageReachable.contains(ref))
                        .collect(Collectors.toCollection(LinkedHashSet::new));
                check(unreachable.isEmpty(), "Components from the SBOM of " + component.ref() + " are not reachable from the package: " + unreachable);
            }
        }
    }

    static Map<String, Set<String>> dependencyGraph(JsonNode bom) {
        Map<String, Set<String>> graph = new HashMap<>();
        for (JsonNode dependency : bom.path("dependencies")) {
            Set<String> targets = graph.computeIfAbsent(dependency.path("ref").asText(), ref -> new HashSet<>());
            dependency.path("dependsOn").forEach(target -> targets.add(target.asText()));
        }
        return graph;
    }

    static Set<String> reachableFrom(String start, Map<String, Set<String>> graph) {
        Set<String> reachable = new HashSet<>();
        Deque<String> queue = new ArrayDeque<>(List.of(start));
        while (!queue.isEmpty()) {
            String ref = queue.pop();
            if (reachable.add(ref)) {
                queue.addAll(graph.getOrDefault(ref, Set.of()));
            }
        }
        return reachable;
    }

    static Map<String, String> hashes(Path file) {
        Map<String, MessageDigest> digests = new LinkedHashMap<>();
        try {
            for (String alg : HASH_ALGORITHMS) {
                digests.put(alg, MessageDigest.getInstance(alg));
            }
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
        byte[] buffer = new byte[1 << 16];
        try (InputStream in = Files.newInputStream(file)) {
            int read;
            while ((read = in.read(buffer)) != -1) {
                for (MessageDigest digest : digests.values()) {
                    digest.update(buffer, 0, read);
                }
            }
        } catch (IOException e) {
            throw new SbomException("Failed to read " + file, e);
        }
        Map<String, String> result = new LinkedHashMap<>();
        digests.forEach((alg, digest) -> result.put(alg, HexFormat.of().formatHex(digest.digest())));
        return result;
    }

    static ArrayNode hashesJson(Map<String, String> hashes) {
        ArrayNode json = JsonNodeFactory.instance.arrayNode();
        hashes.forEach((alg, content) -> json.addObject().put("alg", alg).put("content", content));
        return json;
    }

    private static long size(Path file) {
        try {
            return Files.size(file);
        } catch (IOException e) {
            throw new SbomException("Failed to read " + file, e);
        }
    }

    private static boolean isEmptyDirectory(Path directory) {
        try (Stream<Path> entries = Files.list(directory)) {
            return entries.findAny().isEmpty();
        } catch (IOException e) {
            throw new SbomException("Failed to read " + directory, e);
        }
    }

    private static void checkPurl(String label, String purl) {
        check(purl != null && !purl.isBlank(), label + " has no purl");
        check(purl.startsWith("pkg:") && purl.indexOf('/') > 4, label + " has an invalid purl " + purl);
    }

    private static void putIfPresent(ObjectNode json, String field, String value) {
        if (value != null && !value.isBlank()) {
            json.put(field, value);
        }
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new SbomException(message);
        }
    }

}
