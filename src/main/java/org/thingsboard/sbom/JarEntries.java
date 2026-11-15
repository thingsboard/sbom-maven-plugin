// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
package org.thingsboard.sbom;

import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream;
import org.apache.commons.compress.archivers.zip.ZipFile;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFileAttributeView;
import java.util.Enumeration;
import java.util.Map;
import java.util.jar.Attributes;
import java.util.jar.JarFile;
import java.util.jar.Manifest;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;

/**
 * Puts one entry into a jar: replaces its content, or adds it at the end when the jar has none, with the directories
 * that lead to it. Every other entry is copied without unpacking it, so its compressed bytes, compression method, time,
 * attributes and place in the jar stay as they are. Bytes before the archive, such as the launch script of an executable
 * Spring Boot jar, are kept, with the way the archive counts them in its offsets. A replaced entry keeps its place, time
 * and compression method; an added one takes the time of the first entry of the jar.
 */
final class JarEntries {

    private JarEntries() {}

    /**
     * @param manifestAttributes main attributes to set in the manifest of the jar; the manifest is left as it is when it has them already
     */
    static void put(Path jar, String entryName, byte[] content, Map<String, String> manifestAttributes) {
        Path temp = jar.resolveSibling(jar.getFileName() + ".sbom-tmp");
        try {
            try (ZipFile zip = ZipFile.builder().setPath(jar).get(); ZipArchiveOutputStream out = open(temp, jar, zip)) {
                Enumeration<ZipArchiveEntry> entries = zip.getEntriesInPhysicalOrder();
                long time = zip.getEntriesInPhysicalOrder().nextElement().getTime();
                while (entries.hasMoreElements()) {
                    ZipArchiveEntry entry = entries.nextElement();
                    byte[] replacement = entry.getName().equals(entryName) ? content
                            : entry.getName().equals(JarFile.MANIFEST_NAME) ? manifest(zip, entry, manifestAttributes) : null;
                    if (replacement != null) {
                        write(out, new ZipArchiveEntry(entry), replacement);
                    } else {
                        try (InputStream raw = zip.getRawInputStream(entry)) {
                            out.addRawArchiveEntry(entry, raw);
                        }
                    }
                }
                if (zip.getEntry(entryName) == null) {
                    for (int slash = entryName.indexOf('/'); slash != -1; slash = entryName.indexOf('/', slash + 1)) {
                        String directory = entryName.substring(0, slash + 1);
                        if (zip.getEntry(directory) == null) {
                            ZipArchiveEntry entry = added(directory, time);
                            entry.setMethod(ZipEntry.STORED);
                            write(out, entry, new byte[0]);
                        }
                    }
                    ZipArchiveEntry entry = added(entryName, time);
                    entry.setMethod(ZipEntry.DEFLATED);
                    write(out, entry, content);
                }
            }
            PosixFileAttributeView permissions = Files.getFileAttributeView(jar, PosixFileAttributeView.class);
            if (permissions != null) {
                Files.setPosixFilePermissions(temp, permissions.readAttributes().permissions());
            }
            Files.move(temp, jar, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            try {
                Files.deleteIfExists(temp);
            } catch (IOException ignored) {
                // the first failure is the one to report
            }
            throw new SbomException("Failed to put " + entryName + " into " + jar, e);
        }
    }

    /**
     * The value of a main attribute of the manifest of the jar, or null when the jar has no manifest or the manifest no such attribute.
     */
    static String manifestAttribute(Path jar, String name) {
        try (ZipFile zip = ZipFile.builder().setPath(jar).get()) {
            ZipArchiveEntry entry = zip.getEntry(JarFile.MANIFEST_NAME);
            if (entry == null) {
                return null;
            }
            try (InputStream in = zip.getInputStream(entry)) {
                return new Manifest(in).getMainAttributes().getValue(name);
            }
        } catch (IOException e) {
            throw new SbomException("Failed to read the manifest of " + jar, e);
        }
    }

    /**
     * @return the manifest with the attributes, or null when it has them already
     */
    private static byte[] manifest(ZipFile zip, ZipArchiveEntry entry, Map<String, String> attributes) throws IOException {
        Manifest manifest;
        try (InputStream in = zip.getInputStream(entry)) {
            manifest = new Manifest(in);
        }
        Attributes main = manifest.getMainAttributes();
        if (attributes.entrySet().stream().allMatch(attribute -> attribute.getValue().equals(main.getValue(attribute.getKey())))) {
            return null;
        }
        attributes.forEach(main::putValue);
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        manifest.write(bytes);
        return bytes.toByteArray();
    }

    private static ZipArchiveEntry added(String name, long time) {
        ZipArchiveEntry entry = new ZipArchiveEntry(name);
        entry.setTime(time);
        return entry;
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

    private static void write(ZipArchiveOutputStream out, ZipArchiveEntry entry, byte[] content) throws IOException {
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
