// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
def log = new File(basedir, 'build.log').text
assert log.contains('The image has pkg:npm/left-pad@1.3.0 at /usr/share/app/node_modules/left-pad/package.json, which the SBOM of pkg:maven/org.example.it/app@1.0 does not list')
assert !new File(basedir, 'target/sbom/image-arm64.cdx.json').exists()
true
