// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
package org.thingsboard.sbom;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import static org.thingsboard.sbom.SbomChecks.check;

/**
 * Writes the SBOM of every architecture of a pushed image and attaches it to the image: the work of the {@code image} goal.
 */
final class ImagePublisher {

    private final ImageTools tools;
    private final Consumer<String> log;

    ImagePublisher(ImageTools tools, Consumer<String> log) {
        this.tools = tools;
        this.log = log;
    }

    /**
     * Scans every architecture the tags point to and writes its SBOM to the directory, then attaches each SBOM to its
     * image when {@code attach} is set: nothing is attached unless all are written. Blank tags are ignored.
     * Returns the SBOMs in the order of the architectures.
     */
    List<Path> publish(List<String> tags, String version, String scanExclude, List<BundledComponent> components, Path directory, boolean attach) {
        List<String> pushedTags = tags == null ? List.of()
                : tags.stream().filter(tag -> tag != null && !tag.isBlank()).map(String::strip).distinct().toList();
        check(!pushedTags.isEmpty(), "No image tags configured");
        try {
            Files.createDirectories(directory);
        } catch (IOException e) {
            throw new SbomException("Cannot create " + directory + ": " + e.getMessage(), e);
        }

        ImageReference image = tools.image();
        Map<ImageTools.Platform, Path> sboms = new LinkedHashMap<>();
        for (ImageTools.Platform platform : tools.platforms(pushedTags)) {
            SbomImage.Image described = new SbomImage.Image(image.name(), version, platform.digest(), platform.architecture());
            // Before the scan, which takes the time; the file names also need a digest that is known to be one
            SbomImage.checkImage(described);
            String id = platform.architecture() + "_" + platform.digest().substring("sha256:".length(), "sha256:".length() + 12);
            Path scan = directory.resolve("scan_" + id + ".cdx.json");
            Path sbom = directory.resolve(image.name().replace('/', '_') + "_" + version + "_" + id + ".cdx.json");
            log.accept("Scanning " + image + "@" + platform.digest() + " (" + platform.architecture() + ")");
            tools.scan(platform.digest(), scanExclude, scan);
            SbomImage.write(scan, described, components, sbom);
            log.accept("Wrote image SBOM " + sbom);
            sboms.put(platform, sbom);
        }
        if (!attach) {
            log.accept("Not attaching the image SBOMs: sbom.image.attach is false");
            return List.copyOf(sboms.values());
        }
        sboms.forEach((platform, sbom) -> {
            tools.attach(platform.digest(), sbom);
            log.accept("Attached " + sbom.getFileName() + " to " + image + "@" + platform.digest());
        });
        return List.copyOf(sboms.values());
    }

}
