// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
package org.thingsboard.sbom;

/**
 * A library that the packaging puts into the jar although it is not a Maven dependency of the project,
 * so nothing but this declaration can say what it is. Its file in the jar is {@code <name>-<version>.jar}, where the version starts with
 * a digit or is the {@code Implementation-Version} of the manifest of the library.
 */
public class PackedLibrary {

    private String group;
    private String name;
    private String description;
    private String license;

    public PackedLibrary() {}

    PackedLibrary(String group, String name, String description, String license) {
        this.group = group;
        this.name = name;
        this.description = description;
        this.license = license;
    }

    public String getGroup() {
        return group;
    }

    public String getName() {
        return name;
    }

    public String getDescription() {
        return description;
    }

    public String getLicense() {
        return license;
    }

}
