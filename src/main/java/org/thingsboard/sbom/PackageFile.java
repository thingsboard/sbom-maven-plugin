// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
package org.thingsboard.sbom;

import java.io.File;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import static org.thingsboard.sbom.SbomChecks.check;

public class PackageFile {

    private String id;
    private File file;
    private String purl;
    private boolean skip;

    public PackageFile() {}

    PackageFile(String id, File file, String purl, boolean skip) {
        this.id = id;
        this.file = file;
        this.purl = purl;
        this.skip = skip;
    }

    public String getId() {
        return id;
    }

    public File getFile() {
        return file;
    }

    public String getPurl() {
        return purl;
    }

    public boolean isSkip() {
        return skip;
    }

    /**
     * The ids of the packages, which the bundled and the package goals check alike: there is a package, and every one has
     * an id of its own.
     */
    static Set<String> checkIds(List<PackageFile> packages) {
        check(packages != null && !packages.isEmpty(), "No packages configured");
        Set<String> ids = new LinkedHashSet<>();
        for (PackageFile packageFile : packages) {
            check(packageFile.getId() != null && !packageFile.getId().isBlank(), "A package has no id");
            check(ids.add(packageFile.getId()), "Package id " + packageFile.getId() + " is used more than once");
        }
        return ids;
    }

    /**
     * The name and the version of the packages, which both goals put into what they write.
     */
    static void checkNameAndVersion(String name, String version) {
        check(name != null && !name.isBlank(), "Package name is blank");
        check(version != null && !version.isBlank(), "Package version is blank");
    }

}
