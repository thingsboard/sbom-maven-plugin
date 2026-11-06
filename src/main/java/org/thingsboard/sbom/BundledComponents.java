package org.thingsboard.sbom;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Stream;

final class BundledComponents {

    enum Goal {
        PACKAGE, IMAGE
    }

    private BundledComponents() {
    }

    static void check(List<BundledComponent> components, Goal goal) {
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

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new SbomException(message);
        }
    }

}
