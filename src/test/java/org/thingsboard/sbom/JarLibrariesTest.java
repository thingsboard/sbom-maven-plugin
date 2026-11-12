// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
package org.thingsboard.sbom;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.assertj.core.api.Assertions.assertThat;

class JarLibrariesTest {

    @TempDir
    Path dir;

    @Test
    void readsTheLibrariesOfTheDirectoryWithTheirHashes() throws IOException {
        Path jar = jar();

        assertThat(JarLibraries.read(jar, "BOOT-INF/lib")).extracting(JarLibraries.Library::fileName).containsExactly("plain-1.0.jar", "tools-3.5.8.jar");
        assertThat(JarLibraries.read(jar, "BOOT-INF/lib").get(0).sha256()).hasSize(64);
    }

    @Test
    void givesTheVersionThatALibraryStatesInItsManifest() throws IOException {
        Path jar = jar();

        assertThat(JarLibraries.implementationVersion(jar, "BOOT-INF/lib", "tools-3.5.8.jar")).isEqualTo("3.5.8");
        assertThat(JarLibraries.implementationVersion(jar, "BOOT-INF/lib/", "plain-1.0.jar")).isNull();
    }

    private Path jar() throws IOException {
        Path jar = dir.resolve("app.jar");
        try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(jar))) {
            entry(zip, "BOOT-INF/lib/tools-3.5.8.jar", library("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\nImplementation-Version: 3.5.8\n"));
            entry(zip, "BOOT-INF/lib/plain-1.0.jar", library("A.class", "a"));
            entry(zip, "BOOT-INF/lib/nested/deeper-1.0.jar", library("A.class", "a"));
            entry(zip, "BOOT-INF/classes/not-a-library.jar", library("A.class", "a"));
        }
        return jar;
    }

    private static byte[] library(String name, String content) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(bytes)) {
            entry(zip, name, content.getBytes(StandardCharsets.UTF_8));
        }
        return bytes.toByteArray();
    }

    private static void entry(ZipOutputStream zip, String name, byte[] content) throws IOException {
        zip.putNextEntry(new ZipEntry(name));
        zip.write(content);
        zip.closeEntry();
    }

}
