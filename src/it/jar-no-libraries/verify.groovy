// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
def log = new File(basedir, 'build.log').text
assert log =~ /Jar .*app-1\.0\.jar packs no libraries in BOOT-INF\/lib/
assert !new File(basedir, 'target/classes/META-INF/sbom/application.cdx.json').exists()
true
