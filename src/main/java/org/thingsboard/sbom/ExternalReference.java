// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
package org.thingsboard.sbom;

/**
 * A CycloneDX external reference of a bundled component: a {@code type} of the specification, such as {@code license}
 * for its license file, and the {@code url} where it is.
 */
public class ExternalReference {

    private String type;
    private String url;

    public ExternalReference() {}

    ExternalReference(String type, String url) {
        this.type = type;
        this.url = url;
    }

    public String getType() {
        return type;
    }

    public String getUrl() {
        return url;
    }

}
