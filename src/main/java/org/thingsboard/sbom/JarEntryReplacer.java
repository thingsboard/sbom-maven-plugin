// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
package org.thingsboard.sbom;

import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream;
import org.apache.commons.compress.archivers.zip.ZipFile;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFileAttributeView;
import java.util.Enumeration;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;

/**
 * Replaces the content of one entry of a jar. Every other entry is copied without unpacking it, so its compressed
 * bytes, compression method, time, attributes and place in the jar stay as they are. Bytes before the archive, such as
 * the launch script of an executable Spring Boot jar, are kept, with the way the archive counts them in its offsets.
 * The replaced entry keeps its place, time and compression method.
 */
final class JarEntryReplacer {

    private JarEntryReplacer() {}

    /**
     * @return false when the jar has no such entry; the jar is then left untouched
     */
    static boolean replace(Path jar, String entryName, byte[] content) {
        Path temp = jar.resolveSibling(jar.getFileName() + ".sbom-tmp");
        try {
            try (ZipFile zip = ZipFile.builder().setPath(jar).get()) {
                if (zip.getEntry(entryName) == null) {
                    return false;
                }
                try (ZipArchiveOutputStream out = open(temp, jar, zip)) {
                    Enumeration<ZipArchiveEntry> entries = zip.getEntriesInPhysicalOrder();
                    while (entries.hasMoreElements()) {
                        ZipArchiveEntry entry = entries.nextElement();
                        if (entry.getName().equals(entryName)) {
                            write(out, entry, content);
                        } else {
                            try (InputStream raw = zip.getRawInputStream(entry)) {
                                out.addRawArchiveEntry(entry, raw);
                            }
                        }
                    }
                }
            }
            PosixFileAttributeView permissions = Files.getFileAttributeView(jar, PosixFileAttributeView.class);
            if (permissions != null) {
                Files.setPosixFilePermissions(temp, permissions.readAttributes().permissions());
            }
            Files.move(temp, jar, StandardCopyOption.REPLACE_EXISTING);
            return true;
        } catch (IOException e) {
            try {
                Files.deleteIfExists(temp);
            } catch (IOException ignored) {
                // the first failure is the one to report
            }
            throw new SbomException("Failed to replace " + entryName + " in " + jar, e);
        }
    }

    /**
     * Starts the new archive with the bytes that the jar has before its first entry.
     */
    private static ZipArchiveOutputStream open(Path temp, Path jar, ZipFile zip) throws IOException {
        byte[] preamble;
        try (InputStream in = Files.newInputStream(jar)) {
            preamble = in.readNBytes(Math.toIntExact(zip.getEntriesInPhysicalOrder().nextElement().getLocalHeaderOffset()));
        }
        if (zip.getFirstLocalFileHeaderOffset() == 0) {
            // As Spring Boot writes an executable jar: the offsets of the archive count the preamble
            ZipArchiveOutputStream out = new ZipArchiveOutputStream(temp);
            out.writePreamble(preamble);
            return out;
        }
        // A preamble put before a finished archive: the offsets count from the first entry
        OutputStream file = Files.newOutputStream(temp);
        try {
            file.write(preamble);
            return new ZipArchiveOutputStream(file);
        } catch (IOException e) {
            file.close();
            throw e;
        }
    }

    private static void write(ZipArchiveOutputStream out, ZipArchiveEntry old, byte[] content) throws IOException {
        ZipArchiveEntry entry = new ZipArchiveEntry(old);
        entry.setSize(content.length);
        CRC32 crc = new CRC32();
        crc.update(content);
        entry.setCrc(crc.getValue());
        entry.setCompressedSize(entry.getMethod() == ZipEntry.STORED ? content.length : -1);
        out.putArchiveEntry(entry);
        out.write(content);
        out.closeArchiveEntry();
    }

}
