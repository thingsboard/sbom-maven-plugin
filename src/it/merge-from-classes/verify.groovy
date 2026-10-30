import groovy.json.JsonSlurper

def bom = new JsonSlurper().parse(new File(basedir, 'app/target/classes/META-INF/sbom/application.cdx.json'))
def npm = bom.components.findAll { it.purl.startsWith('pkg:npm/') }
assert npm.size() == 9
def ui = bom.components.find { it.purl.startsWith('pkg:maven/org.example.it/ui@') }
assert ui != null
def uiDependency = bom.dependencies.find { it.ref == ui.'bom-ref' }
assert uiDependency.dependsOn.size() == 6
assert bom.dependencies.every { it.ref != 'thingsboard@4.4.1' }
assert bom.metadata.tools.components*.name.containsAll(['cyclonedx-maven-plugin', 'cyclonedx-npm'])
assert new File(basedir, 'build.log').text.contains('Merged 9 components from org.example.it:ui (META-INF/sbom/ui.cdx.json)')
true
