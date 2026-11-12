// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
def log = new File(basedir, 'build.log').text
assert log =~ /Jar .*app-1\.0\.jar packs no libraries in BOOT-INF\/lib/
// The SBOM is left as the SBOM tool made it
assert new File(basedir, 'target/classes/META-INF/sbom/application.cdx.json').text.contains('pkg:maven/org.springframework.boot/spring-boot@')
true
