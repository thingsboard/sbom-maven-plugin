// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
package org.thingsboard.sbom;

import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * Writes the SBOM of every architecture of a pushed Docker image and attaches it to the image as an OCI referrer artifact.
 * Each SBOM is what Syft finds in the image, with the parts we built replaced by our own SBOMs; the image is the
 * {@code container} root component. Nothing is attached when any check fails. Has no default phase: bind it after the
 * build pushes the image, because it reads the image from the registry. Needs {@code docker} with buildx, {@code syft}
 * and {@code oras}.
 */
@Mojo(name = "image", threadSafe = true)
public class ImageMojo extends SbomMojo {

    /**
     * {@code <namespace>/<name>} of the image, without tag. Docker Hub is the registry unless one comes first,
     * as in {@code registry.example.com/<namespace>/<name>}.
     */
    @Parameter(property = "sbom.image.repository", required = true)
    private String repository;

    /**
     * Every tag the build pushed: the SBOMs cover the images of all of them. Blank tags are ignored.
     */
    @Parameter(property = "sbom.image.tags", defaultValue = "${project.version}", required = true)
    private List<String> tags = new ArrayList<>();

    /**
     * Version of the image component.
     */
    @Parameter(property = "sbom.image.version", defaultValue = "${project.version}", required = true)
    private String version;

    /**
     * Talk to the registry over plain HTTP, for a local test registry.
     */
    @Parameter(property = "sbom.image.plainHttp", defaultValue = "false")
    private boolean plainHttp;

    /**
     * Glob of the image paths Syft must not scan, e.g. the install directory of a package whose SBOM is a bundled component.
     */
    @Parameter(property = "sbom.image.scanExclude")
    private String scanExclude;

    /**
     * Where to write the scans and the image SBOMs.
     */
    @Parameter(property = "sbom.image.outputDirectory", defaultValue = "${project.build.directory}/sbom", required = true)
    private File outputDirectory;

    /**
     * Bundled components, as in the {@code package} goal without {@code packages}, plus
     * {@code installDir} and {@code bundleDir} (absolute paths in the image). A component with an {@code sbom} sets
     * exactly one of {@code file}, {@code installDir} and {@code bundleDir}, which says how its SBOM is checked against the image.
     * {@code @{architecture}} in a version, purl or cpe stands for the architecture of the image.
     */
    @Parameter(required = true)
    private List<BundledComponent> components = new ArrayList<>();

    /**
     * Attach the SBOMs to the image. Set to {@code false} to only write them.
     */
    @Parameter(property = "sbom.image.attach", defaultValue = "true")
    private boolean attach;

    /**
     * The {@code docker} executable.
     */
    @Parameter(property = "sbom.image.docker", defaultValue = "docker", required = true)
    private String docker;

    /**
     * The {@code syft} executable.
     */
    @Parameter(property = "sbom.image.syft", defaultValue = "syft", required = true)
    private String syft;

    /**
     * The {@code oras} executable.
     */
    @Parameter(property = "sbom.image.oras", defaultValue = "oras", required = true)
    private String oras;

    /**
     * Skip the image SBOMs.
     */
    @Parameter(property = "sbom.image.skip", defaultValue = "false")
    private boolean skip;

    @Override
    boolean isSkipped() {
        return skip;
    }

    @Override
    String description() {
        return "image SBOMs";
    }

    @Override
    void run() {
        ImageTools tools = new ImageTools(docker, syft, oras, ImageReference.parse(repository), plainHttp);
        new ImagePublisher(tools, getLog()::info).publish(tags, version, scanExclude, components, outputDirectory.toPath(), attach);
    }

}
