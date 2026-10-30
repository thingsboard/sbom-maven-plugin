package org.thingsboard.sbom;

import org.apache.maven.artifact.Artifact;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.plugins.annotations.ResolutionScope;
import org.apache.maven.project.MavenProject;

import java.io.File;

@Mojo(name = "merge", defaultPhase = LifecyclePhase.PROCESS_RESOURCES, requiresDependencyResolution = ResolutionScope.RUNTIME, threadSafe = true)
public class MergeMojo extends AbstractMojo {

    @Parameter(defaultValue = "${project}", readonly = true, required = true)
    private MavenProject project;

    @Parameter(property = "sbom.merge.targetFile", defaultValue = "${project.build.outputDirectory}/META-INF/sbom/application.cdx.json", required = true)
    private File targetFile;

    @Parameter(property = "sbom.merge.host", required = true)
    private String host;

    @Parameter(property = "sbom.merge.resource")
    private String resource;

    @Parameter(property = "sbom.merge.skip", defaultValue = "false")
    private boolean skip;

    @Override
    public void execute() throws MojoFailureException {
        if (skip) {
            getLog().info("Skipping SBOM merge");
            return;
        }
        String[] coordinates = host == null ? new String[0] : host.split(":", -1);
        if (coordinates.length != 2 || coordinates[0].isBlank() || coordinates[1].isBlank()) {
            throw new MojoFailureException("host must be groupId:artifactId, got '" + host + "'");
        }
        String groupId = coordinates[0];
        String artifactId = coordinates[1];
        Artifact hostArtifact = project.getArtifacts().stream()
                .filter(artifact -> artifact.getGroupId().equals(groupId) && artifact.getArtifactId().equals(artifactId))
                .findFirst()
                .orElseThrow(() -> new MojoFailureException(host + " is not a runtime dependency of " + project.getId()));
        File source = hostArtifact.getFile();
        if (source == null) {
            throw new MojoFailureException(host + " is not resolved to a file");
        }
        String nestedResource = resource == null || resource.isBlank() ? "META-INF/sbom/" + artifactId + ".cdx.json" : resource;
        try {
            int merged = SbomMerger.mergeFile(targetFile.toPath(), source.toPath(), nestedResource, "pkg:maven/" + groupId + "/" + artifactId + "@");
            getLog().info("Merged " + merged + " components from " + host + " (" + nestedResource + ") into " + targetFile);
        } catch (SbomMergeException e) {
            throw new MojoFailureException(e.getMessage(), e);
        }
    }

}
