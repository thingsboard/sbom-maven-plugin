// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
package org.thingsboard.sbom;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Runs what the {@code image} goal does with the real {@code docker buildx}, {@code syft} and {@code oras} against a
 * registry in Docker: the projects in {@code src/it} run the goal with stand-ins for the tools. Skipped without Docker,
 * and when {@code syft} or {@code oras} is missing, except in CI, where they must be installed.
 */
@Testcontainers(disabledWithoutDocker = true)
class RegistryImageIT {

    private static final DockerImageName REGISTRY_IMAGE = DockerImageName.parse("registry:3.0.0");
    private static final String REPOSITORY = "example/tb-mqtt-transport";
    private static final String INSTALL_DIR = "/usr/share/tb-mqtt-transport";
    private static final String APP_JAR = "pkg:maven/org.thingsboard/application@4.4.1-SNAPSHOT";
    private static final String RUNTIME = "pkg:generic/example/runtime@1.0?arch=";
    private static final List<String> TAGS = List.of("latest", "4.4.1");

    @Container
    static final GenericContainer<?> REGISTRY = new GenericContainer<>(REGISTRY_IMAGE).withExposedPorts(5000);

    @TempDir
    static Path tempDir;

    private static ImageTools tools;
    private static List<BundledComponent> components;

    /**
     * Pushes a two-architecture image under two tags, each tag from a build of its own, as the ThingsBoard build does.
     * The image is a Debian system only as far as Syft looks: a package database that lists the tb-mqtt-transport
     * package with a dependency, and the jar the package installs. It runs nothing, so it builds without emulation.
     */
    @BeforeAll
    static void pushTheImage() throws IOException {
        assumeTrue(System.getenv("CI") != null || (installed("syft") && installed("oras")), "syft and oras are not installed");
        ImageReference image = ImageReference.parse("localhost:" + REGISTRY.getMappedPort(5000) + "/" + REPOSITORY);
        tools = new ImageTools("docker", "syft", "oras", image, true);

        Path context = Files.createDirectory(tempDir.resolve("context"));
        Files.writeString(context.resolve("Dockerfile"), "FROM scratch\nCOPY rootfs/ /\n");
        Path rootfs = context.resolve("rootfs");
        write(rootfs.resolve("etc/os-release"), """
                PRETTY_NAME="Debian GNU/Linux 13 (trixie)"
                NAME="Debian GNU/Linux"
                VERSION_ID="13"
                VERSION="13 (trixie)"
                VERSION_CODENAME=trixie
                ID=debian
                """);
        write(rootfs.resolve("var/lib/dpkg/status"), """
                Package: libexample
                Status: install ok installed
                Priority: optional
                Section: libs
                Installed-Size: 10
                Maintainer: Example Maintainers <maintainers@example.com>
                Architecture: all
                Version: 1.2.3-1
                Description: Library the transport depends on

                Package: tb-mqtt-transport
                Status: install ok installed
                Priority: optional
                Section: misc
                Installed-Size: 20
                Maintainer: ThingsBoard <info@thingsboard.io>
                Architecture: all
                Version: 4.4.1-1
                Depends: libexample
                Description: ThingsBoard MQTT transport

                """);
        Path jar = rootfs.resolve(INSTALL_DIR.substring(1)).resolve("bin/application-4.4.1-SNAPSHOT.jar");
        Files.createDirectories(jar.getParent());
        Manifest manifest = new Manifest();
        manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
        try (OutputStream out = Files.newOutputStream(jar); JarOutputStream entries = new JarOutputStream(out, manifest)) {
            entries.putNextEntry(new JarEntry("META-INF/maven/org.thingsboard/application/pom.properties"));
            entries.write("groupId=org.thingsboard\nartifactId=application\nversion=4.4.1-SNAPSHOT\n".getBytes(StandardCharsets.UTF_8));
            entries.closeEntry();
        }
        for (String tag : TAGS) {
            run("docker", "buildx", "build", "--tag", image + ":" + tag, "--platform", "linux/amd64,linux/arm64",
                    "--output", "type=registry", context.toString());
        }

        components = List.of(SbomImageTest.debComponent(tempDir),
                new BundledComponent("application", "example-runtime", "1.0", null).purl(RUNTIME + "@{architecture}"));
    }

    @Test
    void theSbomOfEachArchitectureIsWrittenFromARealScanAndAttached() throws IOException {
        // Each tag is an index of its own, with attestations, over the same two images
        assertThat(tools.index("latest")).isNotEqualTo(tools.index("4.4.1"));
        List<ImageTools.Platform> platforms = tools.platforms(TAGS);
        assertThat(platforms).extracting(ImageTools.Platform::architecture).containsExactly("amd64", "arm64");

        List<Path> sboms = new ImagePublisher(tools, message -> { })
                .publish(TAGS, "4.4.1", INSTALL_DIR + "/**", components, tempDir.resolve("sbom"), true);

        assertThat(sboms).hasSize(2);
        for (int i = 0; i < 2; i++) {
            ImageTools.Platform platform = platforms.get(i);
            String digest = platform.digest();
            String architecture = platform.architecture();
            assertThat(sboms.get(i)).hasFileName("example_tb-mqtt-transport_4.4.1_" + architecture + "_" + digest.substring(7, 19) + ".cdx.json");

            JsonNode described = SbomFiles.readFile(sboms.get(i));
            assertThat(described.path("metadata").path("component").path("purl").asText())
                    .isEqualTo("pkg:docker/" + REPOSITORY + "@" + digest.replace(":", "%3A") + "?arch=" + architecture);
            assertThat(described.path("metadata").path("tools").path("components").findValuesAsText("name")).contains("syft");
            assertThat(described.path("components").findValuesAsText("bom-ref"))
                    .contains(SbomImageTest.DEB_PURL, SbomPackageTest.APP_REF, RUNTIME + architecture)
                    .noneMatch(ref -> ref.startsWith("pkg:deb/debian/tb-mqtt-transport@"));
            // The package of the scan is replaced by ours, which keeps the dependency the scan found
            assertThat(Boms.graph(described).get(SbomImageTest.DEB_PURL))
                    .contains(SbomPackageTest.APP_REF)
                    .anyMatch(ref -> ref.startsWith("pkg:deb/debian/libexample@1.2.3-1"));

            assertThat(attached(digest)).containsExactly(Files.readString(sboms.get(i)));
        }
    }

    @Test
    void theScanSeesTheInstallDirectoryUnlessItIsExcluded() {
        ImageTools.Platform platform = tools.platforms(List.of("4.4.1")).get(0);
        Path excluded = tempDir.resolve("scan-excluded.cdx.json");
        Path scanned = tempDir.resolve("scan.cdx.json");
        SbomImage.Image described = new SbomImage.Image(REPOSITORY, "4.4.1", platform.digest(), platform.architecture());

        tools.scan(platform.digest(), INSTALL_DIR + "/**", excluded);
        tools.scan(platform.digest(), null, scanned);

        assertThat(purls(excluded)).noneMatch(purl -> purl.startsWith(APP_JAR));
        assertThat(purls(scanned)).anyMatch(purl -> purl.startsWith(APP_JAR));
        assertThatThrownBy(() -> SbomImage.write(scanned, described, components, tempDir.resolve("image.cdx.json")))
                .isInstanceOf(SbomException.class);
    }

    @Test
    void aTagThatWasNotPushedIsReportedWithTheMessageOfDocker() {
        assertThatThrownBy(() -> tools.platforms(List.of("not-pushed")))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("docker buildx failed with exit code 1")
                .hasMessageContaining(tools.image() + ":not-pushed");
    }

    /**
     * The contents of the CycloneDX artifacts that refer to the image.
     */
    private static List<String> attached(String digest) throws IOException {
        JsonNode referrers = Boms.MAPPER.readTree(run("oras", "discover", "--plain-http", "--format", "json", tools.image() + "@" + digest));
        List<String> contents = new ArrayList<>();
        for (JsonNode referrer : referrers.findParents("artifactType")) {
            if (!ImageTools.SBOM_MEDIA_TYPE.equals(referrer.path("artifactType").asText())) {
                continue;
            }
            Path directory = Files.createTempDirectory(tempDir, "attached");
            run("oras", "pull", "--plain-http", "--output", directory.toString(), tools.image() + "@" + referrer.path("digest").asText());
            try (var files = Files.list(directory)) {
                for (Path file : files.toList()) {
                    contents.add(Files.readString(file));
                }
            }
        }
        return contents;
    }

    private static List<String> purls(Path sbom) {
        return SbomFiles.readFile(sbom).path("components").findValuesAsText("purl");
    }

    private static void write(Path file, String content) throws IOException {
        Files.createDirectories(file.getParent());
        Files.writeString(file, content);
    }

    private static boolean installed(String tool) {
        try {
            ImageTools.run(tool, null, Map.of(), List.of(tool, "version"));
            return true;
        } catch (SbomException e) {
            return false;
        }
    }

    private static String run(String... command) {
        return ImageTools.run(command[0], tempDir, Map.of(), List.of(command));
    }

}
