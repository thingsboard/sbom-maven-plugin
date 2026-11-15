// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
package org.thingsboard.sbom;

/**
 * A library that the packaging puts into the jar although it is not a Maven dependency of the project, such as the
 * {@code spring-boot-jarmode-tools} of Spring Boot. Its file in the jar is {@code <name>-<version>.jar}, where the version starts with
 * a digit or is the {@code Implementation-Version} of the manifest of the library. What else the SBOM says about it comes from its pom,
 * which Maven takes from the repositories of the project.
 */
public class PackedLibrary {
    private String group;
    private String name;

    public PackedLibrary() {}

    PackedLibrary(String group, String name) {
        this.group = group;
        this.name = name;
    }

    public String getGroup() {
        return group;
    }

    public String getName() {
        return name;
    }

    /**
     * The version of this library when {@code fileName} is its file, or null when it is the file of something else.
     *
     * @param statedVersion the {@code Implementation-Version} of the file, read only when the file name gives no plain version
     */
    String versionIn(String fileName, java.util.function.Supplier<String> statedVersion) {
        String prefix = name + "-";
        if (!fileName.startsWith(prefix) || !fileName.endsWith(".jar")) {
            return null;
        }
        String version = fileName.substring(prefix.length(), fileName.length() - ".jar".length());
        return !version.isEmpty() && (Character.isDigit(version.charAt(0)) || version.equals(statedVersion.get())) ? version : null;
    }
}
