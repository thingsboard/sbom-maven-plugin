// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
package org.thingsboard.sbom;

import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * Writes the SBOM of one architecture of a pushed Docker image: what a scanner such as Syft found in the image,
 * with the parts we built replaced by our own SBOMs. The image is the {@code container} root component.
 * No image SBOM is written when any check fails. Has no default phase: run it once per architecture after the image
 * is pushed, because it needs that architecture's digest and a scan of the image.
 */
@Mojo(name = "image", threadSafe = true)
public class ImageMojo extends AbstractMojo {

    /**
     * CycloneDX SBOM of the image from a scanner, with the location of each component in {@code syft:location:0:path}.
     */
    @Parameter(property = "sbom.image.osSbom", required = true)
    private File osSbom;

    /**
     * {@code <namespace>/<name>} of the image, without registry or tag.
     */
    @Parameter(property = "sbom.image.repository", required = true)
    private String repository;

    /**
     * Version of the image component.
     */
    @Parameter(property = "sbom.image.tag", defaultValue = "${project.version}", required = true)
    private String tag;

    /**
     * {@code sha256:} digest of this architecture's image manifest, not of the multi-architecture index.
     */
    @Parameter(property = "sbom.image.digest", required = true)
    private String digest;

    /**
     * Architecture of the image, e.g. {@code amd64}.
     */
    @Parameter(property = "sbom.image.architecture", required = true)
    private String architecture;

    /**
     * Where to write the image SBOM.
     */
    @Parameter(property = "sbom.image.outputFile", required = true)
    private File outputFile;

    /**
     * Bundled components, at least one: as in the {@code package} goal without {@code packages}, plus
     * {@code installDir} and {@code bundleDir} (absolute paths in the image). A component with an {@code sbom} sets
     * exactly one of {@code file}, {@code installDir} and {@code bundleDir}, which says how its SBOM is checked against the image.
     */
    @Parameter
    private List<BundledComponent> components = new ArrayList<>();

    /**
     * Skip the image SBOM.
     */
    @Parameter(property = "sbom.image.skip", defaultValue = "false")
    private boolean skip;

    @Override
    public void execute() throws MojoFailureException {
        if (skip) {
            getLog().info("Skipping image SBOM");
            return;
        }
        SbomImage.Image image = new SbomImage.Image(repository, tag, digest, architecture);
        try {
            SbomImage.write(osSbom.toPath(), image, components, outputFile.toPath());
        } catch (SbomException e) {
            throw new MojoFailureException(e.getMessage(), e);
        }
        getLog().info("Wrote image SBOM " + outputFile + " for " + repository + "@" + digest + " (" + architecture + ")");
    }

}
