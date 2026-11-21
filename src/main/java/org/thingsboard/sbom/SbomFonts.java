// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
package org.thingsboard.sbom;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Hash;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.stream.Stream;

import static org.thingsboard.sbom.SbomChecks.check;

/**
 * Builds a CycloneDX 1.6 SBOM from the TrueType/OpenType font files bundled inside a library's resources directory.
 * Fonts with the same family, version, license and copyright are grouped into one component whose nested {@code file}
 * components record each font's path and hashes so {@link NestedFiles} can verify them when folded into an application
 * jar SBOM.
 */
final class SbomFonts {

    private SbomFonts() {}

    record Result(ObjectNode bom, int families, int files) {}

    static Result describe(String groupId, String artifactId, String version, Component tool,
                           Path resourcesDirectory, String directory, Map<String, String> licenseOverrides,
                           boolean reproducible) {
        check(resourcesDirectory != null && Files.isDirectory(resourcesDirectory),
                "Resources directory " + resourcesDirectory + " does not exist");
        Path resourcesRoot = resourcesDirectory.toAbsolutePath().normalize();
        Path fontDir = directory == null || directory.isBlank()
                ? resourcesRoot
                : resourcesRoot.resolve(directory).normalize();
        check(fontDir.startsWith(resourcesRoot),
                "Font directory " + directory + " must be inside resources directory " + resourcesDirectory);
        check(Files.isDirectory(fontDir), "Font directory " + fontDir + " does not exist");

        List<Path> fontFiles = collectFontFiles(fontDir);
        check(!fontFiles.isEmpty(), "No .ttf or .otf font files found in " + fontDir);

        Map<GroupKey, List<FontFile>> groups = new TreeMap<>();
        for (Path fontFile : fontFiles) {
            String location = resourcesRoot.relativize(fontFile.toAbsolutePath().normalize()).toString().replace('\\', '/');
            FontMetadata meta = FontMetadata.read(fontFile);
            String license = meta.identifyLicense(location, licenseOverrides);
            Map<String, String> hashes = SbomFiles.hashes(fontFile);
            GroupKey key = new GroupKey(meta.family(), meta.version(), license, meta.copyright());
            groups.computeIfAbsent(key, ignored -> new ArrayList<>())
                    .add(new FontFile(fontFile.getFileName().toString(), location, hashes));
        }

        String specVersion = MavenComponents.SPEC_VERSION.getVersionString();
        String rootRef = "fonts:" + groupId + ":" + artifactId + "@" + version;

        ArrayNode components = JsonNodeFactory.instance.arrayNode();
        Map<String, Set<String>> graph = new LinkedHashMap<>();
        Set<String> rootDependsOn = graph.computeIfAbsent(rootRef, ignored -> new LinkedHashSet<>());
        Map<String, Integer> baseRefCounts = new HashMap<>();

        for (Map.Entry<GroupKey, List<FontFile>> entry : groups.entrySet()) {
            GroupKey group = entry.getKey();
            List<FontFile> files = entry.getValue();
            files.sort(Comparator.comparing(FontFile::location));

            String slug = slug(group.family());
            // Scope bom-ref to the carrying library so two libraries bundling the same font family never collide on merge.
            String baseRef = rootRef + "|font:" + slug + (group.version().isEmpty() ? "" : "@" + group.version());
            int seen = baseRefCounts.merge(baseRef, 1, Integer::sum);
            String groupRef = seen == 1 ? baseRef : baseRef + "#" + seen;
            String purl = genericPurl(slug, group.version());

            ObjectNode component = components.addObject();
            component.put("type", "file");
            component.put("name", group.family());
            SbomJson.putIfPresent(component, "version", group.version());
            component.put("bom-ref", groupRef);
            component.put("purl", purl);
            SbomJson.putIfPresent(component, "copyright", group.copyright());
            SbomJson.putLicense(component, group.license());

            ArrayNode children = component.putArray("components");
            Set<String> groupDependsOn = graph.computeIfAbsent(groupRef, ignored -> new LinkedHashSet<>());
            for (FontFile file : files) {
                String childRef = groupRef + "|" + file.location();
                ObjectNode child = children.addObject();
                child.put("type", "file");
                child.put("name", file.fileName());
                child.put("bom-ref", childRef);
                child.set("hashes", SbomJson.hashesJson(file.hashes()));
                child.putObject("evidence").putArray("occurrences").addObject().put("location", file.location());
                groupDependsOn.add(childRef);
                graph.computeIfAbsent(childRef, ignored -> new LinkedHashSet<>());
            }
            rootDependsOn.add(groupRef);
        }

        ObjectNode bom = SbomJson.newBom(specVersion, "fonts:" + rootRef + ":" + components);
        ObjectNode metadata = bom.putObject("metadata");
        metadata.putArray("lifecycles").addObject().put("phase", "build");
        if (tool != null) {
            addTool(metadata, tool);
        }
        ObjectNode root = metadata.putObject("component");
        root.put("type", "library");
        SbomJson.putIfPresent(root, "group", groupId);
        root.put("name", artifactId);
        root.put("version", version);
        root.put("bom-ref", rootRef);
        ArrayNode properties = metadata.putArray("properties");
        properties.addObject().put("name", "maven.goal").put("value", "fonts");
        if (reproducible) {
            properties.addObject().put("name", "cdx:reproducible").put("value", "enabled");
        }
        bom.set("components", components);
        SbomJson.putDependencies(bom, graph);

        SbomChecks.checkInput("Fonts", bom);
        Set<String> unreachable = SbomChecks.unreachable(SbomChecks.componentRefs(bom), SbomChecks.reachableFrom(rootRef, graph));
        check(unreachable.isEmpty(), "Fonts SBOM has components that are not reachable from its root: " + unreachable);
        return new Result(bom, groups.size(), fontFiles.size());
    }

    private static void addTool(ObjectNode metadata, Component tool) {
        ObjectNode node = metadata.putObject("tools").putArray("components").addObject();
        node.put("type", tool.getType() != null ? tool.getType().getTypeName() : "library");
        SbomJson.putIfPresent(node, "group", tool.getGroup());
        SbomJson.putIfPresent(node, "name", tool.getName());
        SbomJson.putIfPresent(node, "version", tool.getVersion());
        SbomJson.putIfPresent(node, "description", tool.getDescription());
        if (tool.getHashes() != null && !tool.getHashes().isEmpty()) {
            ArrayNode hashes = node.putArray("hashes");
            for (Hash hash : tool.getHashes()) {
                hashes.addObject().put("alg", hash.getAlgorithm()).put("content", hash.getValue());
            }
        }
    }

    private static String genericPurl(String slug, String version) {
        try {
            return new PackageURL(PackageURL.StandardTypes.GENERIC, null, slug,
                    version == null || version.isEmpty() ? null : version, null, null).canonicalize();
        } catch (MalformedPackageURLException e) {
            throw new SbomException("Cannot build a package URL for font '" + slug + "' version '" + version + "'", e);
        }
    }

    private static List<Path> collectFontFiles(Path fontDir) {
        try (Stream<Path> walk = Files.walk(fontDir)) {
            return walk.filter(Files::isRegularFile)
                    .filter(SbomFonts::isFontFile)
                    .sorted()
                    .toList();
        } catch (IOException e) {
            throw new SbomException("Failed to scan font directory " + fontDir, e);
        }
    }

    private static boolean isFontFile(Path path) {
        String name = path.getFileName().toString().toLowerCase(Locale.ROOT);
        return name.endsWith(".ttf") || name.endsWith(".otf");
    }

    private static String slug(String family) {
        String cleaned = family.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]+", "-").replaceAll("^-|-$", "");
        return cleaned.isEmpty() ? "font" : cleaned;
    }

    private record GroupKey(String family, String version, String license, String copyright) implements Comparable<GroupKey> {
        private static final Comparator<GroupKey> ORDER = Comparator.comparing(GroupKey::family)
                .thenComparing(GroupKey::version)
                .thenComparing(GroupKey::license)
                .thenComparing(GroupKey::copyright);

        @Override
        public int compareTo(GroupKey other) {
            return ORDER.compare(this, other);
        }
    }

    private record FontFile(String fileName, String location, Map<String, String> hashes) {}
}
