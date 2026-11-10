// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
def log = new File(basedir, 'build.log').text
assert log.contains('The image has pkg:npm/left-pad@1.3.0 at /usr/share/app/node_modules/left-pad/package.json, which the SBOM of pkg:maven/org.example.it/app@1.0 does not list')
assert !new File(basedir, 'target/sbom/example_app_1.0_arm64_a99a84223d27.cdx.json').exists()
assert !new File(basedir, 'target/sbom/oras.log').exists()
true
