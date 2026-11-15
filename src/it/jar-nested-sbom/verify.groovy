// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
import groovy.json.JsonSlurper

import java.util.zip.ZipFile

def sbomFile = new File(basedir, 'app/target/classes/META-INF/sbom/application.cdx.json')
def bom = new JsonSlurper().parse(sbomFile)
assert bom.components.count { it.purl.startsWith('pkg:npm/') } == 9
def ui = bom.components.find { it.purl.startsWith('pkg:maven/org.example.it/ui@') }
assert ui != null
// The direct dependencies of the nested SBOM are dependencies of the library that carries it
assert bom.dependencies.find { it.ref == ui.'bom-ref' }.dependsOn.size() == 6
assert bom.dependencies.every { it.ref != 'thingsboard@4.4.1' }
assert bom.metadata.tools.components*.name.containsAll(['sbom-maven-plugin', 'cyclonedx-npm'])
assert new File(basedir, 'build.log').text.contains('Adding 9 components from org.example.it:ui (META-INF/sbom/ui.cdx.json)')

new ZipFile(new File(basedir, 'app/target/app-1.0-boot.jar')).withCloseable {
    assert it.getInputStream(it.getEntry('META-INF/sbom/application.cdx.json')).bytes == sbomFile.bytes
}
true
