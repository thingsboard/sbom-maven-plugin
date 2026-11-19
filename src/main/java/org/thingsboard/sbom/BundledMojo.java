// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
package org.thingsboard.sbom;

import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;

import java.io.File;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Writes the bundled SBOM of every distribution package to {@code <outputDirectory>/<name>-<package id>.bundled.cdx.json}:
 * the components the package bundles besides the application, as the build declares them. A package that bundles nothing
 * gets one without components, so that whatever reads it can count on it. The {@code package} goal adds it to the SBOM of
 * the package. Runs at {@code prepare-package} by default: before the packages are built, once the files of the components
 * are in place. No bundled SBOM is written when any check fails.
 */
@Mojo(name = "bundled", defaultPhase = LifecyclePhase.PREPARE_PACKAGE, threadSafe = true)
public class BundledMojo extends SbomMojo {

    /**
     * Name of the package component, as the {@code package} goal is given it.
     */
    @Parameter(property = "sbom.package.name", defaultValue = "${project.artifactId}", required = true)
    private String name;

    /**
     * Version of the package component, as the {@code package} goal is given it.
     */
    @Parameter(property = "sbom.package.version", defaultValue = "${project.version}", required = true)
    private String version;

    /**
     * Packages, each with an {@code id} and an optional {@code skip}; their files and purls are not needed here.
     */
    @Parameter(required = true)
    private List<PackageFile> packages = new ArrayList<>();

    /**
     * Bundled components: {@code type} (default {@code library}), {@code group}, {@code name}, {@code version},
     * {@code description}, {@code purl}, {@code cpe}, {@code license} (an SPDX expression, or the build fails), {@code supplier}, {@code file},
     * {@code sbom} (CycloneDX SBOM of {@code file}; replaces all the other details) and {@code packages}
     * (ids of the packages that contain it; all when empty).
     */
    @Parameter
    private List<BundledComponent> components = new ArrayList<>();

    /**
     * Directory to write the bundled SBOMs to.
     */
    @Parameter(property = "sbom.bundled.directory", defaultValue = "${project.build.directory}/sbom", required = true)
    private File outputDirectory;

    /**
     * Skip all packages.
     */
    @Parameter(property = "sbom.bundled.skip", defaultValue = "false")
    private boolean skip;

    @Override
    boolean isSkipped() {
        return skip;
    }

    @Override
    String description() {
        return "bundled SBOMs";
    }

    @Override
    void run() {
        List<BundledComponent> bundled = components == null ? List.of() : components;
        SbomBundled.checkConfig(packages, bundled);
        packages.stream().filter(PackageFile::isSkip).forEach(packageFile -> getLog().info("Skipping bundled SBOM for " + packageFile.getId()));
        for (Path output : SbomBundled.writeAll(outputDirectory.toPath(), name, version, packages, bundled)) {
            getLog().info("Wrote bundled SBOM " + output);
        }
    }

}
