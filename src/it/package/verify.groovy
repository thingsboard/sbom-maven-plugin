import groovy.json.JsonSlurper

def deb = new JsonSlurper().parse(new File(basedir, 'dist/app.deb.cdx.json'))
assert deb.metadata.component.purl == 'pkg:deb/example/app@1.0.0-1?arch=all'
assert deb.metadata.component.name == 'app'
assert deb.metadata.component.version == '1.0.0'
assert deb.metadata.component.hashes*.alg == ['SHA-256', 'SHA-512']
def debRefs = deb.components*.'bom-ref'
assert debRefs.contains('pkg:maven/org.example.it/app@1.0?type=jar')
assert debRefs.containsAll(['extension@1.0.0', 'registry', 'Root CA'])
assert !debRefs.contains('pkg:maven/com.example/service-wrapper@2.0.1?type=exe')
def extension = deb.components.find { it.'bom-ref' == 'extension@1.0.0' }
assert extension.supplier == [name: 'Example, Inc.', url: ['https://example.org']]
assert extension.licenses == [[expression: 'Apache-2.0']]
assert deb.components.find { it.'bom-ref' == 'Root CA' }.cryptoProperties.certificateProperties.notValidAfter == '2038-01-15T12:00:00Z'
assert deb.dependencies.find { it.ref == 'pkg:deb/example/app@1.0.0-1?arch=all' }.dependsOn.size() == 5
def widgetRef = 'pkg:github/example/widget@0123456789abcdef0123456789abcdef01234567'
assert debRefs.containsAll([widgetRef, 'pkg:npm/charts@1.0.0'])
assert deb.components.find { it.'bom-ref' == widgetRef }.hashes*.alg == ['SHA-256', 'SHA-512']
assert deb.dependencies.find { it.ref == widgetRef }.dependsOn == ['pkg:npm/charts@1.0.0']
assert deb.metadata.tools.components*.name.contains('cyclonedx-npm')

def zip = new JsonSlurper().parse(new File(basedir, 'dist/app-windows.zip.cdx.json'))
assert zip.components*.'bom-ref'.contains('pkg:maven/com.example/service-wrapper@2.0.1?type=exe')
assert zip.serialNumber != deb.serialNumber

assert !new File(basedir, 'dist/app.rpm.cdx.json').exists()
def log = new File(basedir, 'build.log').text
assert log.contains('Skipping package SBOM for rpm')
assert log.contains('Wrote package SBOM ')
true
