// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
import groovy.json.JsonSlurper

def imageRef = 'pkg:docker/example/app@sha256%3A40c308b73fdf1f4fd3375881e6812825b42906b13cfef47e00c7dbe774391778?arch=amd64'
def debRef = 'pkg:deb/example/app@1.0.0-1?arch=all'
def libcRef = 'pkg:deb/debian/libc6@2.41-12?arch=amd64&distro=debian-13.7&package-id=2dc9b457970cbedd'
def sboms = new File(basedir, 'target/sbom')
def image = new JsonSlurper().parse(new File(sboms, 'example_app_1.0_amd64_40c308b73fdf.cdx.json'))
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

// Both tags point to the same two images, and the attestation manifest is not an image: one SBOM per architecture
def arm64Ref = 'pkg:docker/example/app@sha256%3Aa99a84223d27deef5f4c21a5ce0ef4c4772727ee3d0348c0e0fa3c385dc2ecb0?arch=arm64'
def arm64 = new JsonSlurper().parse(new File(sboms, 'example_app_1.0_arm64_a99a84223d27.cdx.json'))
assert arm64.metadata.component.purl == arm64Ref
assert arm64.serialNumber != image.serialNumber
assert new File(basedir, 'syft.log').readLines() == [
        'scan registry:example/app@sha256:40c308b73fdf1f4fd3375881e6812825b42906b13cfef47e00c7dbe774391778 --quiet --exclude /usr/share/app/** --output cyclonedx-json@1.6=' + new File(sboms, 'scan_amd64_40c308b73fdf.cdx.json'),
        'scan registry:example/app@sha256:a99a84223d27deef5f4c21a5ce0ef4c4772727ee3d0348c0e0fa3c385dc2ecb0 --quiet --exclude /usr/share/app/** --output cyclonedx-json@1.6=' + new File(sboms, 'scan_arm64_a99a84223d27.cdx.json')]
assert new File(sboms, 'oras.log').readLines() == [
        'attach --artifact-type application/vnd.cyclonedx+json docker.io/example/app@sha256:40c308b73fdf1f4fd3375881e6812825b42906b13cfef47e00c7dbe774391778 example_app_1.0_amd64_40c308b73fdf.cdx.json:application/vnd.cyclonedx+json',
        'attach --artifact-type application/vnd.cyclonedx+json docker.io/example/app@sha256:a99a84223d27deef5f4c21a5ce0ef4c4772727ee3d0348c0e0fa3c385dc2ecb0 example_app_1.0_arm64_a99a84223d27.cdx.json:application/vnd.cyclonedx+json']
true
