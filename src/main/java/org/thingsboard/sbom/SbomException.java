package org.thingsboard.sbom;

public class SbomException extends RuntimeException {

    public SbomException(String message) {
        super(message);
    }

    public SbomException(String message, Throwable cause) {
        super(message, cause);
    }

}
