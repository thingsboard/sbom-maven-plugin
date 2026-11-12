// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
package org.thingsboard.sbom;

import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

import static org.assertj.core.api.Assertions.assertThat;

class JarEntryReplacerTest {

    private static final String SBOM_ENTRY = "META-INF/sbom/application.cdx.json";
    private static final byte[] NEW_CONTENT = "new".getBytes(StandardCharsets.UTF_8);
    private static final long ENTRY_TIME = 315532800000L;
    private static final byte[] PREAMBLE = "#!/bin/bash\nexec java -jar \"$0\" \"$@\"\n".getBytes(StandardCharsets.UTF_8);

    @TempDir
    Path dir;

    @Test
    void replacesOneEntryAndKeepsTheOthersTheirOrderAndThePreamble() throws IOException {
        Path jar = jar(true);

        assertThat(JarEntryReplacer.replace(jar, SBOM_ENTRY, NEW_CONTENT)).isTrue();

        assertPreambleKept(jar);
        try (ZipFile zip = new ZipFile(jar.toFile())) {
            assertThat(Collections.list(zip.entries())).extracting(ZipEntry::getName).containsExactly("META-INF/MANIFEST.MF", SBOM_ENTRY, "BOOT-INF/lib/a.jar");
            assertThat(zip.getInputStream(zip.getEntry(SBOM_ENTRY)).readAllBytes()).asString().isEqualTo("new");
            assertThat(zip.getInputStream(zip.getEntry("BOOT-INF/lib/a.jar")).readAllBytes()).asString().isEqualTo("library bytes");
            assertThat(zip.getEntry("BOOT-INF/lib/a.jar").getMethod()).isEqualTo(ZipEntry.STORED);
            assertThat(zip.getEntry(SBOM_ENTRY).getTime()).isEqualTo(zip.getEntry("META-INF/MANIFEST.MF").getTime());
        }
    }

    @Test
    void keepsAPreambleThatTheOffsetsOfTheArchiveCount() throws IOException {
        Path jar = dir.resolve("executable.jar");
        try (ZipArchiveOutputStream out = new ZipArchiveOutputStream(jar)) {
            out.writePreamble(PREAMBLE);
            for (String name : List.of("META-INF/MANIFEST.MF", SBOM_ENTRY, "BOOT-INF/classes/A.class")) {
                out.putArchiveEntry(new ZipArchiveEntry(name));
                out.write(("content of " + name).getBytes(StandardCharsets.UTF_8));
                out.closeArchiveEntry();
            }
        }

        assertThat(JarEntryReplacer.replace(jar, SBOM_ENTRY, NEW_CONTENT)).isTrue();

        assertPreambleKept(jar);
        try (ZipFile zip = new ZipFile(jar.toFile())) {
            assertThat(zip.getInputStream(zip.getEntry(SBOM_ENTRY)).readAllBytes()).asString().isEqualTo("new");
            assertThat(zip.getInputStream(zip.getEntry("BOOT-INF/classes/A.class")).readAllBytes()).asString().isEqualTo("content of BOOT-INF/classes/A.class");
        }
    }

    @Test
    void replacesAnEntryOfAZip64Jar() throws IOException {
        int entries = 70_000; // more than the 65,535 that a plain zip can count
        Path jar = dir.resolve("zip64.jar");
        try (ZipArchiveOutputStream out = new ZipArchiveOutputStream(jar)) {
            out.writePreamble(PREAMBLE);
            for (int i = 0; i < entries; i++) {
                out.putArchiveEntry(new ZipArchiveEntry(i == 0 ? SBOM_ENTRY : "BOOT-INF/classes/" + i));
                out.write(Integer.toString(i).getBytes(StandardCharsets.UTF_8));
                out.closeArchiveEntry();
            }
        }

        assertThat(JarEntryReplacer.replace(jar, SBOM_ENTRY, NEW_CONTENT)).isTrue();

        assertPreambleKept(jar);
        try (ZipFile zip = new ZipFile(jar.toFile())) {
            assertThat(zip.size()).isEqualTo(entries);
            assertThat(zip.getInputStream(zip.getEntry(SBOM_ENTRY)).readAllBytes()).asString().isEqualTo("new");
            assertThat(zip.getInputStream(zip.getEntry("BOOT-INF/classes/69999")).readAllBytes()).asString().isEqualTo("69999");
        }
    }

    @Test
    void theSameReplacementGivesTheSameBytes() throws IOException {
        Path first = jar(false);
        byte[] original = Files.readAllBytes(first);
        Path second = dir.resolve("second.jar");
        Files.write(second, original);

        JarEntryReplacer.replace(first, SBOM_ENTRY, NEW_CONTENT);
        JarEntryReplacer.replace(second, SBOM_ENTRY, NEW_CONTENT);

        assertThat(Files.readAllBytes(first)).isEqualTo(Files.readAllBytes(second)).isNotEqualTo(original);
    }

    @Test
    void aJarWithoutTheEntryIsLeftUntouched() throws IOException {
        Path jar = jar(true);
        byte[] original = Files.readAllBytes(jar);

        assertThat(JarEntryReplacer.replace(jar, "META-INF/sbom/other.cdx.json", new byte[0])).isFalse();

        assertThat(Files.readAllBytes(jar)).isEqualTo(original);
    }

    private static void assertPreambleKept(Path jar) throws IOException {
        byte[] bytes = Files.readAllBytes(jar);
        assertThat(bytes).startsWith(PREAMBLE);
        assertThat(new String(bytes, PREAMBLE.length, 4, StandardCharsets.ISO_8859_1)).isEqualTo("PK\u0003\u0004");
    }

    private Path jar(boolean withPreamble) throws IOException {
        ByteArrayOutputStream archive = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(archive)) {
            deflated(zip, "META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n");
            deflated(zip, SBOM_ENTRY, "old old old old old old");
            byte[] library = "library bytes".getBytes(StandardCharsets.UTF_8);
            ZipEntry stored = new ZipEntry("BOOT-INF/lib/a.jar");
            stored.setMethod(ZipEntry.STORED);
            stored.setSize(library.length);
            stored.setCompressedSize(library.length);
            CRC32 crc = new CRC32();
            crc.update(library);
            stored.setCrc(crc.getValue());
            stored.setTime(ENTRY_TIME);
            zip.putNextEntry(stored);
            zip.write(library);
            zip.closeEntry();
        }
        Path jar = dir.resolve("app.jar");
        try (OutputStream out = Files.newOutputStream(jar)) {
            if (withPreamble) {
                out.write(PREAMBLE);
            }
            archive.writeTo(out);
        }
        return jar;
    }

    private static void deflated(ZipOutputStream zip, String name, String content) throws IOException {
        ZipEntry entry = new ZipEntry(name);
        entry.setTime(ENTRY_TIME);
        zip.putNextEntry(entry);
        zip.write(content.getBytes(StandardCharsets.UTF_8));
        zip.closeEntry();
    }

}
