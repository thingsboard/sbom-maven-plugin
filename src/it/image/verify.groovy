// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
import groovy.json.JsonSlurper

def imageRef = 'pkg:docker/example/app@sha256%3A40c308b73fdf1f4fd3375881e6812825b42906b13cfef47e00c7dbe774391778?arch=amd64'
def debRef = 'pkg:deb/example/app@1.0.0-1?arch=all'
def libcRef = 'pkg:deb/debian/libc6@2.41-12?arch=amd64&distro=debian-13.7&package-id=2dc9b457970cbedd'
def image = new JsonSlurper().parse(new File(basedir, 'target/sbom/image-amd64.cdx.json'))
assert image.metadata.component.type == 'container'
assert image.metadata.component.purl == imageRef
assert image.metadata.component.group == 'example'
assert image.metadata.component.name == 'app'
assert image.metadata.component.version == '1.0'
assert image.metadata.component.hashes == [[alg: 'SHA-256', content: '40c308b73fdf1f4fd3375881e6812825b42906b13cfef47e00c7dbe774391778']]
def refs = image.components*.'bom-ref'
assert refs.containsAll(['os:debian@13.7', libcRef, debRef, 'pkg:maven/org.example.it/app@1.0?type=jar'])
assert !refs.contains('pkg:deb/debian/app@1.0.0-1?arch=all&distro=debian-13.7&package-id=c84ed22d92ad12f4')
assert image.dependencies.find { it.ref == imageRef }.dependsOn as Set == ['os:debian@13.7', debRef] as Set
assert image.dependencies.find { it.ref == debRef }.dependsOn as Set == [libcRef, 'pkg:maven/org.example.it/app@1.0?type=jar'] as Set
assert image.metadata.tools.components*.name.contains('syft')
assert new File(basedir, 'build.log').text.contains('Wrote image SBOM ')
true
