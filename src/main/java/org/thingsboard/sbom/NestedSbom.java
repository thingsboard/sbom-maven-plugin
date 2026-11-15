// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
package org.thingsboard.sbom;

/**
 * A packed library that carries the SBOM of what it bundles, such as a web UI built by another tool. The components of
 * that SBOM become components of the jar, as dependencies of the library.
 */
public class NestedSbom {
    private String library;
    private String resource;
    private boolean skip;

    public NestedSbom() {}

    NestedSbom(String library, String resource) {
        this.library = library;
        this.resource = resource;
    }

    /**
     * {@code groupId:artifactId} of the library.
     */
    public String getLibrary() {
        return library;
    }

    /**
     * Path of the SBOM inside the library; {@code META-INF/sbom/<artifactId>.cdx.json} by default.
     */
    public String getResource() {
        return resource;
    }

    /**
     * Leaves the SBOM of the library out, for a build that packs the library without what it bundles.
     */
    public boolean isSkip() {
        return skip;
    }

    /**
     * The group and the artifact id of the library.
     */
    String[] coordinates() {
        String[] coordinates = library == null ? new String[0] : library.split(":", -1);
        SbomChecks.check(coordinates.length == 2 && !coordinates[0].isBlank() && !coordinates[1].isBlank(),
                "The library of a nested SBOM must be groupId:artifactId, got '" + library + "'");
        return coordinates;
    }

    String resourceOr(String defaultResource) {
        return resource == null || resource.isBlank() ? defaultResource : resource;
    }
}
