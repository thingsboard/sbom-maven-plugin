package org.thingsboard.sbom;

import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

@Mojo(name = "image", threadSafe = true)
public class ImageMojo extends AbstractMojo {

    @Parameter(property = "sbom.image.osSbom", required = true)
    private File osSbom;

    @Parameter(property = "sbom.image.repository", required = true)
    private String repository;

    @Parameter(property = "sbom.image.tag", defaultValue = "${project.version}", required = true)
    private String tag;

    @Parameter(property = "sbom.image.digest", required = true)
    private String digest;

    @Parameter(property = "sbom.image.architecture", required = true)
    private String architecture;

    @Parameter(property = "sbom.image.outputFile", required = true)
    private File outputFile;

    @Parameter
    private List<BundledComponent> components = new ArrayList<>();

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
