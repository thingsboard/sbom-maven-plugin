// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
import groovy.json.JsonSlurper

def imageRef = 'pkg:docker/example/app@sha256%3Aa99a84223d27deef5f4c21a5ce0ef4c4772727ee3d0348c0e0fa3c385dc2ecb0?arch=arm64'
def appRef = 'pkg:maven/org.example.it/app@1.0'
def uiRef = 'pkg:maven/org.example.it/ui@1.0'
def chromeRef = 'pkg:generic/google/chrome-for-testing@156.0.8078.4?os=linux&arch=arm64'
def image = new JsonSlurper().parse(new File(basedir, 'target/sbom/image-arm64.cdx.json'))
def refs = image.components*.'bom-ref'
assert refs.containsAll([appRef, uiRef, chromeRef, 'pkg:npm/express@5.1.0', 'pkg:npm/%40example/native@2.0.0',
                         'pkg:npm/%40example/native-linux-arm64@2.0.0', 'pkg:npm/hugerte@1.0.14'])
assert !refs.contains('pkg:npm/%40example/native-linux-x64@2.0.0')
assert refs.findAll { it.contains('?package-id=') } == ['pkg:npm/express@5.1.0?package-id=0000000000000006']
assert image.dependencies.find { it.ref == imageRef }.dependsOn as Set == ['os:debian@12.12', appRef, uiRef, chromeRef,
                                                                          'pkg:npm/express@5.1.0?package-id=0000000000000006'] as Set
assert image.dependencies.find { it.ref == 'pkg:npm/%40example/native@2.0.0' }.dependsOn == ['pkg:npm/%40example/native-linux-arm64@2.0.0']
assert image.metadata.component.manufacturer == [name: 'Example, Inc.']
true
