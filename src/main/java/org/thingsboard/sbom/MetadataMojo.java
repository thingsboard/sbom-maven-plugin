// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
package org.thingsboard.sbom;

import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;

import java.io.File;
import java.util.List;

/**
 * Sets who makes and supplies the software and the SBOM (CycloneDX 1.6 or later).
 * Configured fields replace existing values; fields that are not configured are left as they are.
 * Each organization has a {@code name}, optional {@code urls} and optional {@code contacts} ({@code name}, {@code email}, {@code phone}).
 * The file is left untouched when any check fails. Runs at {@code process-resources} by default.
 */
@Mojo(name = "metadata", defaultPhase = LifecyclePhase.PROCESS_RESOURCES, threadSafe = true)
public class MetadataMojo extends SbomMojo {

    /**
     * SBOM to update, rewritten in place.
     */
    @Parameter(property = "sbom.metadata.targetFile", defaultValue = "${project.build.outputDirectory}/META-INF/sbom/application.cdx.json", required = true)
    private File targetFile;

    /**
     * Organization that created the SBOM; sets {@code metadata.manufacturer}.
     */
    @Parameter
    private Organization manufacturer;

    /**
     * Organization that supplies the software the SBOM describes; sets {@code metadata.supplier}.
     */
    @Parameter
    private Organization supplier;

    /**
     * Organization that created the software the SBOM describes; sets {@code metadata.component.manufacturer}.
     */
    @Parameter
    private Organization componentManufacturer;

    /**
     * Skip setting the metadata.
     */
    @Parameter(property = "sbom.metadata.skip", defaultValue = "false")
    private boolean skip;

    @Override
    boolean isSkipped() {
        return skip;
    }

    @Override
    String description() {
        return "SBOM metadata";
    }

    @Override
    void run() {
        List<String> fields = SbomMetadata.applyToFile(targetFile.toPath(), manufacturer, supplier, componentManufacturer);
        getLog().info("Set " + String.join(", ", fields) + " in " + targetFile);
    }

}
