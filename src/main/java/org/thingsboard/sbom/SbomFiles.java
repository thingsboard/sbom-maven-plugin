// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
package org.thingsboard.sbom;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

final class SbomFiles {

    private static final List<String> HASH_ALGORITHMS = List.of("SHA-256", "SHA-512");
    /**
     * The hashes that an SBOM gives of a library, in the order {@code cyclonedx-maven-plugin} writes them.
     */
    static final List<String> LIBRARY_HASH_ALGORITHMS = List.of("MD5", "SHA-1", "SHA-256", "SHA-512", "SHA-384", "SHA3-384", "SHA3-256", "SHA3-512");
    static final ObjectMapper MAPPER = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

    private SbomFiles() {}

    static JsonNode readFile(Path file) {
        if (!Files.isRegularFile(file)) {
            throw new SbomException("SBOM file " + file + " does not exist");
        }
        try {
            return MAPPER.readTree(file.toFile());
        } catch (IOException e) {
            throw new SbomException("SBOM file " + file + " is not valid JSON", e);
        }
    }

    /**
     * @return the bytes written
     */
    static byte[] writeFile(Path file, JsonNode bom) {
        try {
            Path parent = file.toAbsolutePath().getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            byte[] bytes = MAPPER.writeValueAsBytes(bom);
            Files.write(file, bytes);
            return bytes;
        } catch (IOException e) {
            throw new SbomException("Failed to write " + file, e);
        }
    }

    static Map<String, String> hashes(Path file) {
        return hashes(file, HASH_ALGORITHMS);
    }

    static Map<String, String> hashes(Path file, List<String> algorithms) {
        try (InputStream in = Files.newInputStream(file)) {
            return hashes(in, file.toString(), algorithms);
        } catch (IOException e) {
            throw new SbomException("Failed to read " + file, e);
        }
    }

    static Map<String, String> hashes(InputStream in, String source, List<String> algorithms) {
        Map<String, MessageDigest> digests = new LinkedHashMap<>();
        try {
            for (String alg : algorithms) {
                digests.put(alg, MessageDigest.getInstance(alg));
            }
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
        byte[] buffer = new byte[1 << 16];
        try {
            int read;
            while ((read = in.read(buffer)) != -1) {
                for (MessageDigest digest : digests.values()) {
                    digest.update(buffer, 0, read);
                }
            }
        } catch (IOException e) {
            throw new SbomException("Failed to read " + source, e);
        }
        Map<String, String> result = new LinkedHashMap<>();
        digests.forEach((alg, digest) -> result.put(alg, HexFormat.of().formatHex(digest.digest())));
        return result;
    }

    static JsonNode readResource(Path source, String resource) {
        if (!Files.isRegularFile(source)) {
            throw new SbomException("SBOM source " + source + " does not exist");
        }
        try (ZipFile zip = new ZipFile(source.toFile())) {
            ZipEntry entry = zip.getEntry(resource);
            if (entry == null) {
                throw missingResource(source, resource);
            }
            try (InputStream in = zip.getInputStream(entry)) {
                return MAPPER.readTree(in);
            }
        } catch (IOException e) {
            throw new SbomException("Failed to read " + resource + " from " + source, e);
        }
    }

    private static SbomException missingResource(Path source, String resource) {
        return new SbomException(resource + " not found in " + source
                + ". Rebuild the module that produces it, or skip the nested SBOM");
    }

}
