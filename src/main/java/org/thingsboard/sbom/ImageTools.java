// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
package org.thingsboard.sbom;

import com.fasterxml.jackson.databind.JsonNode;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import static org.thingsboard.sbom.SbomChecks.check;

/**
 * The command-line tools the {@code image} goal runs against the registry of one image: {@code docker buildx} finds the
 * pushed images, {@code syft} scans them and {@code oras} attaches their SBOMs. A tool that fails stops the goal with
 * the tool's own message.
 */
final class ImageTools {

    static final String SBOM_MEDIA_TYPE = "application/vnd.cyclonedx+json";

    /**
     * One architecture of a pushed image: {@code digest} is that of its image manifest.
     */
    record Platform(String architecture, String digest) {}

    private final String docker;
    private final String syft;
    private final String oras;
    private final ImageReference image;
    private final boolean plainHttp;

    ImageTools(String docker, String syft, String oras, ImageReference image, boolean plainHttp) {
        this.docker = docker;
        this.syft = syft;
        this.oras = oras;
        this.image = image;
        this.plainHttp = plainHttp;
    }

    ImageReference image() {
        return image;
    }

    /**
     * The Linux images the tags point to, each once and in the order of the architectures: tags pushed from one build
     * usually share them.
     */
    List<Platform> platforms(List<String> tags) {
        Set<Platform> platforms = new TreeSet<>(Comparator.comparing(Platform::architecture).thenComparing(Platform::digest));
        for (String tag : tags) {
            List<Platform> found = parsePlatforms(image + ":" + tag, index(tag));
            check(!found.isEmpty(), image + ":" + tag + " is not a multi-architecture image with Linux images: push it with docker buildx build --platform");
            platforms.addAll(found);
        }
        return List.copyOf(platforms);
    }

    /**
     * The image index of the tag as the registry holds it. Raw, so that buildx fetches the index alone.
     */
    String index(String tag) {
        return run("docker buildx", null, Map.of(), List.of(docker, "buildx", "imagetools", "inspect", image + ":" + tag, "--raw"));
    }

    static List<Platform> parsePlatforms(String image, String index) {
        JsonNode manifests;
        try {
            manifests = SbomFiles.MAPPER.readTree(index).path("manifests");
        } catch (IOException e) {
            throw new SbomException("docker buildx did not describe " + image + " as JSON: " + index.strip(), e);
        }
        List<Platform> platforms = new ArrayList<>();
        for (JsonNode manifest : manifests) {
            JsonNode platform = manifest.path("platform");
            // Attestation manifests sit in the index next to the images, with the platform unknown/unknown
            if ("linux".equals(platform.path("os").asText())) {
                platforms.add(new Platform(platform.path("architecture").asText(), manifest.path("digest").asText()));
            }
        }
        return platforms;
    }

    /**
     * Writes what Syft finds in the image to {@code output} as a CycloneDX SBOM.
     */
    void scan(String digest, String exclude, Path output) {
        List<String> command = new ArrayList<>(List.of(syft, "scan", "registry:" + image + "@" + digest, "--quiet"));
        if (exclude != null && !exclude.isBlank()) {
            command.addAll(List.of("--exclude", exclude));
        }
        command.addAll(List.of("--output", "cyclonedx-json@1.6=" + output));
        // File metadata would add every file of the image to the SBOM
        run("syft", null, Map.of(
                "SYFT_FILE_METADATA_SELECTION", "none",
                "SYFT_CHECK_FOR_APP_UPDATE", "false",
                "SYFT_REGISTRY_INSECURE_USE_HTTP", String.valueOf(plainHttp)), command);
    }

    /**
     * Whether a CycloneDX SBOM is attached to the image already.
     */
    boolean hasSbom(String digest) {
        List<String> command = orasCommand("discover");
        command.addAll(List.of("--format", "json", "--artifact-type", SBOM_MEDIA_TYPE, image.qualified() + "@" + digest));
        String referrers = run("oras", null, Map.of(), command);
        try {
            return SbomFiles.MAPPER.readTree(referrers).findValuesAsText("artifactType").contains(SBOM_MEDIA_TYPE);
        } catch (IOException e) {
            throw new SbomException("oras did not list what is attached to " + image + "@" + digest + " as JSON: " + referrers.strip(), e);
        }
    }

    /**
     * Attaches the SBOM to the image as an OCI referrer artifact, titled with the file name.
     */
    void attach(String digest, Path sbom) {
        List<String> command = orasCommand("attach");
        command.addAll(List.of("--artifact-type", SBOM_MEDIA_TYPE, image.qualified() + "@" + digest, sbom.getFileName() + ":" + SBOM_MEDIA_TYPE));
        run("oras", sbom.toAbsolutePath().getParent(), Map.of(), command);
    }

    private List<String> orasCommand(String subcommand) {
        List<String> command = new ArrayList<>(List.of(oras, subcommand));
        if (plainHttp) {
            command.add("--plain-http");
        }
        return command;
    }

    /**
     * Runs the command and returns what it prints. Fails with what it prints as errors when it cannot run or fails.
     */
    static String run(String tool, Path directory, Map<String, String> environment, List<String> command) {
        Path errors = null;
        try {
            errors = Files.createTempFile("sbom-" + tool.replace(' ', '-'), ".err");
            ProcessBuilder builder = new ProcessBuilder(command).redirectError(errors.toFile());
            if (directory != null) {
                builder.directory(directory.toFile());
            }
            builder.environment().putAll(environment);
            Process process;
            try {
                process = builder.start();
            } catch (IOException e) {
                throw new SbomException("Cannot run " + command.get(0) + ": " + tool + " must be installed and on the PATH (" + e.getMessage() + ")", e);
            }
            process.getOutputStream().close();
            String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            int exitCode = process.waitFor();
            if (exitCode != 0) {
                String message = Files.readString(errors).strip();
                throw new SbomException(tool + " failed with exit code " + exitCode + ": " + String.join(" ", command)
                        + (message.isEmpty() ? "" : System.lineSeparator() + message)
                        + (rateLimited(message) ? System.lineSeparator() + "The registry's rate limit is reached: run the build again later" : ""));
            }
            return output;
        } catch (IOException e) {
            throw new SbomException("Running " + tool + " failed: " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new SbomException("Interrupted while running " + tool, e);
        } finally {
            if (errors != null) {
                errors.toFile().delete();
            }
        }
    }

    private static boolean rateLimited(String message) {
        String lower = message.toLowerCase();
        return lower.contains("toomanyrequests") || lower.contains("429 too many requests");
    }

}
