// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
def log = new File(basedir, 'build.log').text
assert log.contains('docker buildx failed with exit code 1: ')
assert log.contains('buildx imagetools inspect example/app:1.0 --raw')
// The message of the tool itself
assert log.contains('data/manifest-1.0.json')
assert !new File(basedir, 'target/sbom/oras.log').exists()
true
