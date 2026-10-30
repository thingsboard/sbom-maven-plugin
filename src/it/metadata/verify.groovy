import groovy.json.JsonSlurper

def bom = new JsonSlurper().parse(new File(basedir, 'app/target/classes/META-INF/sbom/application.cdx.json'))
assert bom.metadata.manufacturer == [name: 'Example, Inc.', url: ['https://example.org'], contact: [[email: 'security@example.org']]]
assert bom.metadata.supplier == [name: 'Example, Inc.']
assert bom.metadata.component.manufacturer == [name: 'Example, Inc.', url: ['https://example.org']]
assert bom.components.count { it.purl.startsWith('pkg:npm/') } == 9
def log = new File(basedir, 'build.log').text
assert log.contains('Set metadata.manufacturer, metadata.supplier, metadata.component.manufacturer in ')
assert log.contains('Merged 9 components from org.example.it:ui')
def jar = new java.util.zip.ZipFile(new File(basedir, 'app/target/app-1.0.jar'))
try {
    def packaged = new JsonSlurper().parse(jar.getInputStream(jar.getEntry('META-INF/sbom/application.cdx.json')))
    assert packaged.metadata.manufacturer.name == 'Example, Inc.'
} finally {
    jar.close()
}
true
