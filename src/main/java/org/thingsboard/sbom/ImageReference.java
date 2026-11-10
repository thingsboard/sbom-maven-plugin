// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
package org.thingsboard.sbom;

/**
 * A pushed image without tag or digest: {@code name} is {@code <namespace>/<name>}, and {@code registry} is null for Docker Hub.
 */
record ImageReference(String registry, String name) {

    private static final String DOCKER_HUB = "docker.io";

    /**
     * Reads {@code [<registry>/]<namespace>/<name>} as Docker does: the first part is a registry when it looks like a host.
     */
    static ImageReference parse(String repository) {
        String host = repository == null ? "" : repository.substring(0, Math.max(repository.indexOf('/'), 0));
        boolean hasRegistry = host.contains(".") || host.contains(":") || host.equals("localhost");
        String name = hasRegistry ? repository.substring(host.length() + 1) : repository;
        SbomImage.checkRepository(name);
        return new ImageReference(hasRegistry ? host : null, name);
    }

    /**
     * The image as docker and syft take it.
     */
    @Override
    public String toString() {
        return registry == null ? name : registry + "/" + name;
    }

    /**
     * The image with its registry spelled out, as oras takes it.
     */
    String qualified() {
        return (registry == null ? DOCKER_HUB : registry) + "/" + name;
    }

}
