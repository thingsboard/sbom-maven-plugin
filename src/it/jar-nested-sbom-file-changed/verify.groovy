// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
def log = new File(basedir, 'build.log').text
assert log =~ /The SHA-256 of fonts\/demo\/Demo-Regular\.ttf in org\.example\.it:ui is [0-9a-f]{64}, but its SBOM gives [0-9a-f]{64} for demo-font@1\.0\|Demo-Regular\.ttf/
assert !new File(basedir, 'app/target/sbom/application.cdx.json').exists()
true
