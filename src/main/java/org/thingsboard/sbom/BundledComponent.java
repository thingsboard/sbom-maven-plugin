// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
package org.thingsboard.sbom;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

public class BundledComponent {

    private static final String ARCHITECTURE = "@{architecture}";

    private String type = "library";
    private String group;
    private String name;
    private String version;
    private String description;
    private String purl;
    private String cpe;
    private String license;
    private Organization supplier;
    private File file;
    private File sbom;
    private String installDir;
    private String bundleDir;
    private List<String> packages = new ArrayList<>();

    public BundledComponent() {}

    private BundledComponent(BundledComponent other) {
        this.type = other.type;
        this.group = other.group;
        this.name = other.name;
        this.version = other.version;
        this.description = other.description;
        this.purl = other.purl;
        this.cpe = other.cpe;
        this.license = other.license;
        this.supplier = other.supplier;
        this.file = other.file;
        this.sbom = other.sbom;
        this.installDir = other.installDir;
        this.bundleDir = other.bundleDir;
        this.packages = other.packages;
    }

    BundledComponent(String type, String name, String version, File file) {
        this.type = type;
        this.name = name;
        this.version = version;
        this.file = file;
    }

    BundledComponent group(String group) {
        this.group = group;
        return this;
    }

    BundledComponent description(String description) {
        this.description = description;
        return this;
    }

    BundledComponent purl(String purl) {
        this.purl = purl;
        return this;
    }

    BundledComponent cpe(String cpe) {
        this.cpe = cpe;
        return this;
    }

    BundledComponent license(String license) {
        this.license = license;
        return this;
    }

    BundledComponent supplier(Organization supplier) {
        this.supplier = supplier;
        return this;
    }

    BundledComponent sbom(File sbom) {
        this.sbom = sbom;
        return this;
    }

    BundledComponent installDir(String installDir) {
        this.installDir = installDir;
        return this;
    }

    BundledComponent bundleDir(String bundleDir) {
        this.bundleDir = bundleDir;
        return this;
    }

    BundledComponent packages(List<String> packages) {
        this.packages = packages;
        return this;
    }

    public String getType() {
        return type;
    }

    public String getGroup() {
        return group;
    }

    public String getName() {
        return name;
    }

    public String getVersion() {
        return version;
    }

    public String getDescription() {
        return description;
    }

    public String getPurl() {
        return purl;
    }

    public String getCpe() {
        return cpe;
    }

    public String getLicense() {
        return license;
    }

    public Organization getSupplier() {
        return supplier;
    }

    public File getFile() {
        return file;
    }

    public File getSbom() {
        return sbom;
    }

    public String getInstallDir() {
        return installDir;
    }

    public String getBundleDir() {
        return bundleDir;
    }

    public List<String> getPackages() {
        return packages == null ? List.of() : packages;
    }

    /**
     * The component for one architecture of an image: {@code @{architecture}} in its version, purl and cpe is replaced.
     */
    BundledComponent forArchitecture(String architecture) {
        BundledComponent component = new BundledComponent(this);
        component.version = forArchitecture(version, architecture);
        component.purl = forArchitecture(purl, architecture);
        component.cpe = forArchitecture(cpe, architecture);
        return component;
    }

    private static String forArchitecture(String value, String architecture) {
        return value == null ? null : value.replace(ARCHITECTURE, architecture);
    }

    String ref() {
        if (sbom != null && (name == null || name.isBlank())) {
            return "sbom " + sbom;
        }
        if (purl != null && !purl.isBlank()) {
            return purl;
        }
        return version == null || version.isBlank() ? name : name + "@" + version;
    }

    List<String> configuredValues() {
        List<String> values = new ArrayList<>(Arrays.asList(type, group, name, version, description, purl, cpe, license, installDir, bundleDir,
                file == null ? null : file.getPath(), sbom == null ? null : sbom.getPath()));
        values.addAll(getPackages());
        if (supplier != null) {
            values.add(supplier.getName());
            values.addAll(supplier.getUrls());
            supplier.getContacts().forEach(contact -> values.addAll(Arrays.asList(contact.getName(), contact.getEmail(), contact.getPhone())));
        }
        values.removeIf(Objects::isNull);
        return values;
    }

    boolean includedIn(String packageId) {
        return getPackages().isEmpty() || getPackages().contains(packageId);
    }

}
