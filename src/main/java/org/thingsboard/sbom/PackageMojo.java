// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
package org.thingsboard.sbom;

import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;

import java.io.File;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Writes one SBOM per distribution package ({@code .deb}, {@code .rpm}, {@code .zip}) to {@code <package file>.cdx.json}.
 * The package becomes the root component and depends on the application SBOM's root and on the bundled components it contains.
 * No package SBOM is written when any check fails. Runs at {@code package} by default: declare the plugin after the
 * plugins that build the packages, so it runs after them in the same phase.
 */
@Mojo(name = "package", defaultPhase = LifecyclePhase.PACKAGE, threadSafe = true)
public class PackageMojo extends AbstractMojo {

    /**
     * Application SBOM to start from.
     */
    @Parameter(property = "sbom.package.sourceFile", defaultValue = "${project.build.outputDirectory}/META-INF/sbom/application.cdx.json", required = true)
    private File sourceFile;

    /**
     * Name of the package component.
     */
    @Parameter(property = "sbom.package.name", defaultValue = "${project.artifactId}", required = true)
    private String name;

    /**
     * Version of the package component.
     */
    @Parameter(property = "sbom.package.version", defaultValue = "${project.version}", required = true)
    private String version;

    /**
     * Packages to describe, each with an {@code id}, the package {@code file}, its {@code purl} and an optional {@code skip}.
     */
    @Parameter(required = true)
    private List<PackageFile> packages = new ArrayList<>();

    /**
     * Bundled components: {@code type} (default {@code library}), {@code group}, {@code name}, {@code version},
     * {@code description}, {@code purl}, {@code cpe}, {@code license} (SPDX expression), {@code supplier}, {@code file},
     * {@code sbom} (CycloneDX SBOM of {@code file}; replaces all the other details) and {@code packages}
     * (ids of the packages that contain it; all when empty).
     */
    @Parameter
    private List<BundledComponent> components = new ArrayList<>();

    /**
     * Skip all packages.
     */
    @Parameter(property = "sbom.package.skip", defaultValue = "false")
    private boolean skip;

    @Override
    public void execute() throws MojoFailureException {
        if (skip) {
            getLog().info("Skipping package SBOMs");
            return;
        }
        List<BundledComponent> bundled = components == null ? List.of() : components;
        try {
            SbomPackage.checkConfig(packages, bundled);
            packages.stream().filter(PackageFile::isSkip).forEach(packageFile -> getLog().info("Skipping package SBOM for " + packageFile.getId()));
            for (Path output : SbomPackage.writeAll(sourceFile.toPath(), name, version, packages, bundled)) {
                getLog().info("Wrote package SBOM " + output);
            }
        } catch (SbomException e) {
            throw new MojoFailureException(e.getMessage(), e);
        }
    }

}
