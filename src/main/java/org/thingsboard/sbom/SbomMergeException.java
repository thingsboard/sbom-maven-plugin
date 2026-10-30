package org.thingsboard.sbom;

public class SbomMergeException extends RuntimeException {

    public SbomMergeException(String message) {
        super(message);
    }

    public SbomMergeException(String message, Throwable cause) {
        super(message, cause);
    }

}
