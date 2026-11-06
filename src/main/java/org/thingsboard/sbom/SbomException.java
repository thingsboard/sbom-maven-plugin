// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
package org.thingsboard.sbom;

public class SbomException extends RuntimeException {

    public SbomException(String message) {
        super(message);
    }

    public SbomException(String message, Throwable cause) {
        super(message, cause);
    }

}
