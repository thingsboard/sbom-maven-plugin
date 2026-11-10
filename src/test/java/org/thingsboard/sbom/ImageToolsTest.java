// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
package org.thingsboard.sbom;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ImageToolsTest {

    private static final String AMD64 = SbomImageTest.DIGEST;
    private static final String ARM64 = SbomImageTest.OTHER_DIGEST;

    @Test
    void platformsAreTheLinuxImagesOfTheIndex() {
        String index = """
                {
                  "mediaType": "application/vnd.oci.image.index.v1+json",
                  "manifests": [
                    {"digest": "%s", "platform": {"architecture": "amd64", "os": "linux"}},
                    {"digest": "sha256:6243dec9286873e0392f0527f96c394684dc6fa12661f0bd19253dcd5561e70a",
                     "annotations": {"vnd.docker.reference.type": "attestation-manifest"},
                     "platform": {"architecture": "unknown", "os": "unknown"}},
                    {"digest": "%s", "platform": {"architecture": "arm64", "os": "linux"}}
                  ]
                }
                """.formatted(AMD64, ARM64);

        assertThat(ImageTools.parsePlatforms("example/app:1.0", index))
                .containsExactly(new ImageTools.Platform("amd64", AMD64), new ImageTools.Platform("arm64", ARM64));
    }

    @Test
    void anImageThatIsNotAnIndexHasNoPlatforms() {
        String manifest = """
                {"mediaType": "application/vnd.oci.image.manifest.v1+json", "config": {"digest": "%s"}}
                """.formatted(AMD64);

        assertThat(ImageTools.parsePlatforms("example/app:1.0", manifest)).isEmpty();
    }

    @Test
    void outputThatIsNotJsonIsReported() {
        assertThatThrownBy(() -> ImageTools.parsePlatforms("example/app:1.0", "Name: example/app:1.0"))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("docker buildx did not describe example/app:1.0 as JSON: Name: example/app:1.0");
    }

    @Test
    void aMissingToolIsNamed(@TempDir Path directory) {
        ImageTools tools = new ImageTools("no-such-docker", "no-such-syft", "no-such-oras", ImageReference.parse("example/app"), false);

        assertThatThrownBy(() -> tools.platforms(List.of("1.0")))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("Cannot run no-such-docker: docker buildx must be installed and on the PATH");
        assertThatThrownBy(() -> tools.scan(AMD64, null, directory.resolve("scan.cdx.json")))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("Cannot run no-such-syft: syft must be installed and on the PATH");
        assertThatThrownBy(() -> tools.attach(AMD64, directory.resolve("image.cdx.json")))
                .isInstanceOf(SbomException.class)
                .hasMessageContaining("Cannot run no-such-oras: oras must be installed and on the PATH");
    }

    @Test
    void anImageIsOnDockerHubUnlessItNamesARegistry() {
        ImageReference onDockerHub = ImageReference.parse("thingsboard/tb-node");
        assertThat(onDockerHub).isEqualTo(new ImageReference(null, "thingsboard/tb-node")).hasToString("thingsboard/tb-node");
        assertThat(onDockerHub.qualified()).isEqualTo("docker.io/thingsboard/tb-node");
        // Docker Hub spelled out is the same image
        assertThat(ImageReference.parse("docker.io/thingsboard/tb-node")).isEqualTo(onDockerHub);
        assertThat(ImageReference.parse("index.docker.io/thingsboard/tb-node")).isEqualTo(onDockerHub);

        for (String registry : List.of("localhost:5000", "localhost", "registry.example.com")) {
            ImageReference elsewhere = ImageReference.parse(registry + "/thingsboard/tb-node");
            assertThat(elsewhere).isEqualTo(new ImageReference(registry, "thingsboard/tb-node")).hasToString(registry + "/thingsboard/tb-node");
            assertThat(elsewhere.qualified()).isEqualTo(registry + "/thingsboard/tb-node");
        }
    }

    @Test
    void anImageWithoutNamespaceIsRejected() {
        for (String repository : new String[] {null, "tb-node", "localhost:5000/tb-node", "registry.example.com/a/b/c"}) {
            assertThatThrownBy(() -> ImageReference.parse(repository))
                    .isInstanceOf(SbomException.class)
                    .hasMessageContaining("must be <namespace>/<name>");
        }
    }

}
