// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
def sboms = new File(basedir, 'target/sbom')
def log = new File(basedir, 'build.log').text
// The amd64 image passes its checks and the arm64 image, which comes after it, does not: neither gets an SBOM
assert new File(sboms, 'example_app_1.0_amd64_40c308b73fdf.cdx.json').exists()
assert !new File(sboms, 'example_app_1.0_arm64_a99a84223d27.cdx.json').exists()
assert log.contains('The image installs app 9.9.9-1, but the SBOM of pkg:deb/example/app@1.0.0-1?arch=all is for 1.0.0-1')
assert log.contains('Wrote image SBOM ')
assert !log.contains('Attached ')
assert !new File(sboms, 'oras.log').exists()
true
