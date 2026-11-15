// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
assert !new File(basedir, 'app/target/sbom/application.cdx.json').exists()
assert new File(basedir, 'build.log').text.contains('Skipping SBOM of the jar')
true
