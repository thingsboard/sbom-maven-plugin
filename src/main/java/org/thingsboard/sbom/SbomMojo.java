// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
package org.thingsboard.sbom;

import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.Parameter;

/**
 * What every goal shares: it can be skipped on its own or with all the others, and a failed check fails the build.
 */
public abstract class SbomMojo extends AbstractMojo {

    /**
     * Skip every goal of the plugin.
     */
    @Parameter(property = "sbom.skip", defaultValue = "false")
    private boolean skipAll;

    @Override
    public final void execute() throws MojoFailureException {
        if (skipAll || isSkipped()) {
            getLog().info("Skipping " + description());
            return;
        }
        try {
            run();
        } catch (SbomException e) {
            throw new MojoFailureException(e.getMessage(), e);
        }
    }

    /**
     * The {@code skip} parameter of the goal.
     */
    abstract boolean isSkipped();

    /**
     * What the goal makes, for the log.
     */
    abstract String description();

    abstract void run() throws MojoFailureException;

}
