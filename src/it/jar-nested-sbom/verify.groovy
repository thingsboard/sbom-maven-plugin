// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
import groovy.json.JsonSlurper

import java.util.zip.ZipFile

def sbomFile = new File(basedir, 'app/target/sbom/application.cdx.json')
def bom = new JsonSlurper().parse(sbomFile)
assert bom.components.count { it.purl.startsWith('pkg:npm/') } == 9
def ui = bom.components.find { it.purl.startsWith('pkg:maven/org.example.it/ui@') }
assert ui != null
// The direct dependencies of the nested SBOM are dependencies of the library that carries it
assert bom.dependencies.find { it.ref == ui.'bom-ref' }.dependsOn.size() == 7
assert bom.dependencies.every { it.ref != 'thingsboard@4.4.1' }
assert bom.metadata.tools.components*.name.containsAll(['sbom-maven-plugin', 'cyclonedx-npm'])
// A file that the nested SBOM places in the library is checked against its hashes, and keeps its place under its component
def font = bom.components.find { it.'bom-ref' == 'demo-font@1.0' }
assert font.components*.evidence.occurrences.location == [['fonts/demo/Demo-Regular.ttf']]
assert bom.dependencies.find { it.ref == ui.'bom-ref' }.dependsOn.contains('demo-font@1.0')
def log = new File(basedir, 'build.log').text
assert log.contains('Checked the 1 file that the SBOM of org.example.it:ui places in the library')
assert log.contains('Adding 10 components from org.example.it:ui (META-INF/sbom/ui.cdx.json)')

new ZipFile(new File(basedir, 'app/target/app-1.0-boot.jar')).withCloseable {
    assert it.getInputStream(it.getEntry('META-INF/sbom/application.cdx.json')).bytes == sbomFile.bytes
}
true
