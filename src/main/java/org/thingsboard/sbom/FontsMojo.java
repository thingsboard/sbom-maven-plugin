// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
package org.thingsboard.sbom;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.maven.plugin.descriptor.PluginDescriptor;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.MavenProject;

import java.io.File;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Generates a CycloneDX 1.6 SBOM from the {@code .ttf} and {@code .otf} font files bundled in a module's resources
 * directory, reading version, copyright and license metadata from each font's OpenType {@code name} table. By default
 * the SBOM is written to {@code META-INF/sbom/<artifactId>.cdx.json} inside the module's classes directory at
 * {@code process-classes}, so {@code maven-jar-plugin} packs it into the jar and the {@code jar} goal folds it
 * automatically into application jar SBOMs.
 */
@Mojo(name = "fonts", defaultPhase = LifecyclePhase.PROCESS_CLASSES, threadSafe = true)
public class FontsMojo extends SbomMojo {

    @Parameter(defaultValue = "${project}", readonly = true, required = true)
    private MavenProject project;

    @Parameter(defaultValue = "${plugin}", readonly = true, required = true)
    private PluginDescriptor plugin;

    /**
     * Root directory of the resources packed into the jar (relative paths from this directory become the
     * {@code evidence.occurrences[].location} values verified by {@link NestedFiles}).
     */
    @Parameter(property = "sbom.fonts.resourcesDirectory", defaultValue = "${project.build.outputDirectory}", required = true)
    private File resourcesDirectory;

    /**
     * Subdirectory under {@link #resourcesDirectory} that holds the font files (empty scans {@link #resourcesDirectory}).
     */
    @Parameter(property = "sbom.fonts.directory", defaultValue = "fonts")
    private String directory;

    /**
     * Where the generated font SBOM is written, or the existing CycloneDX SBOM to merge into when {@link #merge} is
     * {@code true}.
     */
    @Parameter(property = "sbom.fonts.outputFile", defaultValue = "${project.build.outputDirectory}/META-INF/sbom/${project.artifactId}.cdx.json", required = true)
    private File outputFile;

    /**
     * Optional SPDX license overrides ({@code font} path or family name and {@code license} SPDX expression), for fonts
     * whose OpenType {@code name} table carries no recognizable license information.
     */
    @Parameter
    private List<FontLicense> licenses = new ArrayList<>();

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
     * When the SBOM was made; sets {@code metadata.timestamp}. By default the time Maven builds reproducibly with: a
     * date and time with an offset ({@code 2026-01-31T12:00:00Z}) or seconds since 1970. Not set, or left at the
     * {@code 1980-02-01T00:00:00Z} that Maven sets by itself, {@code metadata.timestamp} is omitted. Ignored when
     * {@link #merge} is {@code true}, which preserves the target SBOM's existing timestamp.
     */
    @Parameter(property = "sbom.fonts.timestamp", defaultValue = "${project.build.outputTimestamp}")
    private String timestamp;

    /**
     * When {@code true}, merge the font components into an existing CycloneDX SBOM at {@link #outputFile} (attaching
     * them to its root component) instead of writing a standalone font SBOM.
     */
    @Parameter(property = "sbom.fonts.merge", defaultValue = "false")
    private boolean merge;

    /**
     * Skip the font SBOM.
     */
    @Parameter(property = "sbom.fonts.skip", defaultValue = "false")
    private boolean skip;

    @Override
    boolean isSkipped() {
        return skip;
    }

    @Override
    String description() {
        return "SBOM of the bundled fonts";
    }

    @Override
    void run() {
        Path target = outputFile.toPath();
        JsonNode existing = merge ? SbomFiles.readFile(target) : null;
        String time = merge ? null : SbomMetadata.timestamp(timestamp);
        SbomFonts.Result result = SbomFonts.describe(
                project.getGroupId(),
                project.getArtifactId(),
                project.getVersion(),
                MavenComponents.tool(plugin),
                resourcesDirectory.toPath(),
                directory,
                FontLicense.toMap(licenses),
                time != null
        );
        ObjectNode bom = merge ? SbomMerger.mergeIntoRoot(existing, result.bom()) : result.bom();
        if (manufacturer != null || supplier != null || componentManufacturer != null || time != null) {
            bom = SbomMetadata.apply(bom, manufacturer, supplier, componentManufacturer, time);
        }
        SbomFiles.writeFile(target, bom);
        String summary = result.families() + " font " + (result.families() == 1 ? "family" : "families")
                + " (" + result.files() + " " + (result.files() == 1 ? "file" : "files") + ")";
        getLog().info(merge ? "Merged " + summary + " into " + outputFile : "Wrote " + outputFile + " with " + summary);
    }
}
