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

@Mojo(name = "package", defaultPhase = LifecyclePhase.PACKAGE, threadSafe = true)
public class PackageMojo extends AbstractMojo {

    @Parameter(property = "sbom.package.sourceFile", defaultValue = "${project.build.outputDirectory}/META-INF/sbom/application.cdx.json", required = true)
    private File sourceFile;

    @Parameter(property = "sbom.package.name", defaultValue = "${project.artifactId}", required = true)
    private String name;

    @Parameter(property = "sbom.package.version", defaultValue = "${project.version}", required = true)
    private String version;

    @Parameter(required = true)
    private List<PackageFile> packages = new ArrayList<>();

    @Parameter
    private List<BundledComponent> components = new ArrayList<>();

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
            for (PackageFile packageFile : packages) {
                if (packageFile.isSkip()) {
                    getLog().info("Skipping package SBOM for " + packageFile.getId());
                    continue;
                }
                Path output = SbomPackage.writeFor(sourceFile.toPath(), name, version, packageFile, bundled);
                getLog().info("Wrote package SBOM " + output);
            }
        } catch (SbomException e) {
            throw new MojoFailureException(e.getMessage(), e);
        }
    }

}
