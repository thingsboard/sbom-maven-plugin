package org.thingsboard.sbom;

import java.io.File;

public class PackageFile {

    private String id;
    private File file;
    private String purl;
    private boolean skip;

    public PackageFile() {
    }

    public PackageFile(String id, File file, String purl, boolean skip) {
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

}
