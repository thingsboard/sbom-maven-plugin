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
 * Writes one SBOM per distribution package ({@code .deb}, {@code .rpm}, {@code .zip}) to {@code <package file>.cdx.json}.
 * The package becomes the root component and depends on the application SBOM's root and on the components that the bundled
 * SBOM of the package lists, which the {@code bundled} goal writes. No package SBOM is written when any check fails. Runs at
 * {@code package} by default: declare the plugin after the plugins that build the packages, so it runs after them in the
 * same phase.
 */
@Mojo(name = "package", defaultPhase = LifecyclePhase.PACKAGE, threadSafe = true)
public class PackageMojo extends SbomMojo {

    /**
     * Application SBOM to start from.
     */
    @Parameter(property = "sbom.package.sourceFile", defaultValue = "${project.build.directory}/sbom/application.cdx.json", required = true)
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
     * Directory with the bundled SBOMs of the packages, {@code <name>-<package id>.bundled.cdx.json}, which the
     * {@code bundled} goal writes.
     */
    @Parameter(property = "sbom.bundled.directory", defaultValue = "${project.build.directory}/sbom", required = true)
    private File bundledDirectory;

    /**
     * Skip all packages.
     */
    @Parameter(property = "sbom.package.skip", defaultValue = "false")
    private boolean skip;

    @Override
    boolean isSkipped() {
        return skip;
    }

    @Override
    String description() {
        return "package SBOMs";
    }

    @Override
    void run() {
        SbomPackage.checkConfig(packages);
        packages.stream().filter(PackageFile::isSkip).forEach(packageFile -> getLog().info("Skipping package SBOM for " + packageFile.getId()));
        for (Path output : SbomPackage.writeAll(sourceFile.toPath(), bundledDirectory.toPath(), name, version, packages)) {
            getLog().info("Wrote package SBOM " + output);
        }
    }

}
