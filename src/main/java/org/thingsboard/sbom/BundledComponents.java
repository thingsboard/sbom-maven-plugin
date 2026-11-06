// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
package org.thingsboard.sbom;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Stream;

import static org.thingsboard.sbom.SbomChecks.check;
import static org.thingsboard.sbom.SbomJson.hashesJson;
import static org.thingsboard.sbom.SbomJson.putIfPresent;

final class BundledComponents {

    enum Goal {
        PACKAGE, IMAGE
    }

    private BundledComponents() {
    }

    static void validate(List<BundledComponent> components, Goal goal) {
        Set<String> refs = new HashSet<>();
        for (BundledComponent component : components) {
            checkResolved(component);
            if (component.getSbom() == null) {
                check(component.getName() != null && !component.getName().isBlank(), "A bundled component has no name");
            } else {
                checkNoDetails(component);
            }
            if (goal == Goal.PACKAGE) {
                checkPackageAnchor(component);
            } else {
                checkImageAnchors(component);
            }
            check(refs.add(component.ref()), "Bundled component " + component.ref() + " is declared more than once");
        }
    }

    private static void checkResolved(BundledComponent component) {
        component.configuredValues().forEach(value -> check(!value.contains("${"), "Bundled component " + component.ref()
                + " has the unresolved property in " + value + "; define it, or pass it on the command line when the goal runs on its own"));
    }

    private static void checkNoDetails(BundledComponent component) {
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
    }

    private static void checkPackageAnchor(BundledComponent component) {
        check(component.getInstallDir() == null && component.getBundleDir() == null,
                "Bundled component " + component.ref() + " sets installDir or bundleDir, which only apply to image SBOMs");
        check(component.getSbom() == null || component.getFile() != null,
                "Bundled component " + component.ref() + " has an SBOM but no file to check it against");
    }

    private static void checkImageAnchors(BundledComponent component) {
        check(component.getPackages().isEmpty(), "Bundled component " + component.ref() + " sets packages, which only apply to package SBOMs");
        if (component.getSbom() == null) {
            check(component.getInstallDir() == null && component.getBundleDir() == null,
                    "Bundled component " + component.ref() + " sets installDir or bundleDir, which need an SBOM to check the image against");
        } else {
            List<String> anchors = new ArrayList<>();
            if (component.getFile() != null) {
                anchors.add("file");
            }
            if (component.getInstallDir() != null) {
                anchors.add("installDir");
            }
            if (component.getBundleDir() != null) {
                anchors.add("bundleDir");
            }
            check(anchors.size() == 1, "Bundled component " + component.ref() + " must set exactly one of file, installDir and bundleDir to check its SBOM against, but sets "
                    + anchors);
        }
        Stream.of(component.getInstallDir(), component.getBundleDir()).filter(Objects::nonNull).forEach(dir ->
                check(dir.startsWith("/") && !dir.endsWith("/") && !dir.contains("//"),
                        "Bundled component " + component.ref() + " has the directory " + dir + ", which must be an absolute path in the image without a trailing slash"));
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
            Map<String, String> actual = SbomFiles.hashes(file);
            actual.forEach((alg, content) -> check(!declared.containsKey(alg) || declared.get(alg).equals(content),
                    label + " was built for a file with " + alg + " " + declared.get(alg) + ", but " + file + " has " + content
                            + "; copy the SBOM that was built together with this file"));
            root.set("hashes", hashesJson(actual));
        }
        Set<String> unreachable = SbomChecks.unreachable(SbomChecks.componentRefs(nested), SbomChecks.reachableFrom(ref, SbomChecks.dependencyGraph(nested)));
        check(unreachable.isEmpty(), label + " has components that its root does not depend on: " + unreachable);
        return new Resolved(ref, root, nested);
    }

    record Resolved(String ref, ObjectNode json, JsonNode sbom) {
    }

    private static ObjectNode toJson(BundledComponent component) {
        ObjectNode json = JsonNodeFactory.instance.objectNode();
        json.put("type", component.getType() == null || component.getType().isBlank() ? "library" : component.getType());
        json.put("bom-ref", component.ref());
        if (component.getSupplier() != null) {
            json.set("supplier", SbomMetadata.toJson("Supplier of bundled component " + component.ref(), component.getSupplier()));
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
                json.set("hashes", hashesJson(SbomFiles.hashes(file)));
            }
        }
        if (component.getLicense() != null && !component.getLicense().isBlank()) {
            json.putArray("licenses").addObject().put("expression", component.getLicense());
        }
        if (component.getPurl() != null && !component.getPurl().isBlank()) {
            SbomChecks.checkPurl("Bundled component " + component.getName(), component.getPurl());
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

    private static boolean isEmptyDirectory(Path directory) {
        try (Stream<Path> entries = Files.list(directory)) {
            return entries.findAny().isEmpty();
        } catch (IOException e) {
            throw new SbomException("Failed to read " + directory, e);
        }
    }

}
