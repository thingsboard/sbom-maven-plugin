// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
package org.thingsboard.sbom;

import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;

import java.io.File;
import java.util.List;

@Mojo(name = "metadata", defaultPhase = LifecyclePhase.PROCESS_RESOURCES, threadSafe = true)
public class MetadataMojo extends AbstractMojo {

    @Parameter(property = "sbom.metadata.targetFile", defaultValue = "${project.build.outputDirectory}/META-INF/sbom/application.cdx.json", required = true)
    private File targetFile;

    @Parameter
    private Organization manufacturer;

    @Parameter
    private Organization supplier;

    @Parameter
    private Organization componentManufacturer;

    @Parameter(property = "sbom.metadata.skip", defaultValue = "false")
    private boolean skip;

    @Override
    public void execute() throws MojoFailureException {
        if (skip) {
            getLog().info("Skipping SBOM metadata");
            return;
        }
        try {
            List<String> fields = SbomMetadata.applyToFile(targetFile.toPath(), manufacturer, supplier, componentManufacturer);
            getLog().info("Set " + String.join(", ", fields) + " in " + targetFile);
        } catch (SbomException e) {
            throw new MojoFailureException(e.getMessage(), e);
        }
    }

}
