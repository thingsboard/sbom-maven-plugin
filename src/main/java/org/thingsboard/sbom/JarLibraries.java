// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
package org.thingsboard.sbom;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.jar.Attributes;
import java.util.jar.JarFile;
import java.util.jar.Manifest;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;

/**
 * The libraries packed inside a jar: every {@code .jar} entry directly under one directory of it.
 */
final class JarLibraries {

    /**
     * One packed library: the name of its file and the hashes of its bytes, those of {@link SbomFiles#LIBRARY_HASH_ALGORITHMS}.
     */
    record Library(String fileName, Map<String, String> hashes) {

        String sha256() {
            return hashes.get("SHA-256");
        }

    }

    private JarLibraries() {}

    static List<Library> read(Path jar, String directory) {
        String prefix = prefix(directory);
        List<Library> libraries = new ArrayList<>();
        try (ZipFile zip = new ZipFile(jar.toFile())) {
            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                String name = entry.getName();
                if (entry.isDirectory() || !name.startsWith(prefix) || !name.endsWith(".jar")) {
                    continue;
                }
                String fileName = name.substring(prefix.length());
                if (fileName.contains("/")) {
                    continue;
                }
                try (InputStream in = zip.getInputStream(entry)) {
                    libraries.add(new Library(fileName, SbomFiles.hashes(in, jar + "!/" + name, SbomFiles.LIBRARY_HASH_ALGORITHMS)));
                }
            }
        } catch (IOException e) {
            throw new SbomException("Failed to read the libraries of " + jar, e);
        }
        libraries.sort(Comparator.comparing(Library::fileName));
        return libraries;
    }

    private static String prefix(String directory) {
        return directory.endsWith("/") ? directory : directory + "/";
    }

    /**
     * The version a packed library states about itself, as {@code Implementation-Version} in its manifest, or null when it states none.
     */
    static String implementationVersion(Path jar, String directory, String fileName) {
        String name = prefix(directory) + fileName;
        try (ZipFile zip = new ZipFile(jar.toFile()); ZipInputStream library = new ZipInputStream(zip.getInputStream(zip.getEntry(name)))) {
            for (ZipEntry entry = library.getNextEntry(); entry != null; entry = library.getNextEntry()) {
                if (entry.getName().equals(JarFile.MANIFEST_NAME)) {
                    return new Manifest(library).getMainAttributes().getValue(Attributes.Name.IMPLEMENTATION_VERSION);
                }
            }
            return null;
        } catch (IOException e) {
            throw new SbomException("Failed to read the manifest of " + jar + "!/" + name, e);
        }
    }

}
