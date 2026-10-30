package org.thingsboard.sbom;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

final class SbomSource {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private SbomSource() {
    }

    static JsonNode readFile(Path file) {
        if (!Files.isRegularFile(file)) {
            throw new SbomMergeException("SBOM file " + file + " does not exist");
        }
        try {
            return MAPPER.readTree(file.toFile());
        } catch (IOException e) {
            throw new SbomMergeException("SBOM file " + file + " is not valid JSON", e);
        }
    }

    static JsonNode readResource(Path source, String resource) {
        if (Files.isDirectory(source)) {
            Path file = source.resolve(resource);
            if (!Files.isRegularFile(file)) {
                throw missingResource(source, resource);
            }
            return readFile(file);
        }
        if (!Files.isRegularFile(source)) {
            throw new SbomMergeException("SBOM source " + source + " does not exist");
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
            throw new SbomMergeException("Failed to read " + resource + " from " + source, e);
        }
    }

    private static SbomMergeException missingResource(Path source, String resource) {
        return new SbomMergeException(resource + " not found in " + source
                + ". Rebuild the module that produces it, or skip the SBOM merge");
    }

}
