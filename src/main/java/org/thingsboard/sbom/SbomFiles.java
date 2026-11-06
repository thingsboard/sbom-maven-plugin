package org.thingsboard.sbom;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

final class SbomFiles {

    private static final ObjectMapper MAPPER = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

    private SbomFiles() {
    }

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

    static void writeFile(Path file, JsonNode bom) {
        try {
            Path parent = file.toAbsolutePath().getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            MAPPER.writeValue(file.toFile(), bom);
        } catch (IOException e) {
            throw new SbomException("Failed to write " + file, e);
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
                + ". Rebuild the module that produces it, or skip the SBOM merge");
    }

}
