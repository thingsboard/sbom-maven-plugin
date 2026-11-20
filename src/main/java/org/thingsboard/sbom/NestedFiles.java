// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
package org.thingsboard.sbom;

import com.fasterxml.jackson.databind.JsonNode;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Checks the files that a nested SBOM places inside the library that carries it, such as fonts or images that a library
 * bundles. A component of type {@code file}, at any depth, that gives a location in {@code evidence.occurrences} is a
 * file of the library at that path; when it also has hashes, the file must have them. Other components are not checked:
 * an npm package that a web UI bundles into its scripts has no location, and the occurrences of a library can say where
 * the source uses it.
 */
final class NestedFiles {

    private NestedFiles() {}

    /**
     * @return the number of files checked
     */
    static int check(Path library, String libraryName, JsonNode sbom) {
        List<JsonNode> located = new ArrayList<>();
        collect(sbom.path("components"), located);
        if (located.isEmpty()) {
            return 0;
        }
        int files = 0;
        try (ZipFile zip = new ZipFile(library.toFile())) {
            for (JsonNode component : located) {
                Map<String, String> expected = hashes(component, libraryName);
                for (JsonNode occurrence : component.path("evidence").path("occurrences")) {
                    String location = occurrence.path("location").asText();
                    ZipEntry entry = zip.getEntry(location);
                    SbomChecks.check(entry != null && !entry.isDirectory(), "The SBOM of " + libraryName + " places "
                            + label(component) + " at " + location + ", which is not a file of the library");
                    if (!expected.isEmpty()) {
                        Map<String, String> actual;
                        try (InputStream in = zip.getInputStream(entry)) {
                            actual = SbomFiles.hashes(in, location, List.copyOf(expected.keySet()));
                        }
                        expected.forEach((algorithm, value) -> SbomChecks.check(value.equals(actual.get(algorithm)),
                                "The " + algorithm + " of " + location + " in " + libraryName + " is " + actual.get(algorithm)
                                        + ", but its SBOM gives " + value + " for " + label(component)
                                        + ". Update the SBOM to the file, or the file to the SBOM"));
                    }
                    files++;
                }
            }
        } catch (IOException e) {
            throw new SbomException("Failed to read " + library, e);
        }
        return files;
    }

    private static void collect(JsonNode components, List<JsonNode> located) {
        for (JsonNode component : components) {
            if ("file".equals(component.path("type").asText()) && component.path("evidence").path("occurrences").size() > 0) {
                located.add(component);
            }
            collect(component.path("components"), located);
        }
    }

    private static Map<String, String> hashes(JsonNode component, String libraryName) {
        Map<String, String> hashes = new LinkedHashMap<>();
        for (JsonNode hash : component.path("hashes")) {
            String algorithm = hash.path("alg").asText();
            SbomChecks.check(SbomFiles.LIBRARY_HASH_ALGORITHMS.contains(algorithm), "The SBOM of " + libraryName + " gives a "
                    + algorithm + " hash for " + label(component) + ", which cannot be checked; give one of " + SbomFiles.LIBRARY_HASH_ALGORITHMS);
            hashes.put(algorithm, hash.path("content").asText().toLowerCase(Locale.ROOT));
        }
        return hashes;
    }

    private static String label(JsonNode component) {
        String ref = component.path("bom-ref").asText();
        return ref.isEmpty() ? component.path("name").asText() : ref;
    }
}
