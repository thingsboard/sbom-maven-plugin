// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
import groovy.json.JsonSlurper

import java.util.jar.JarFile
import java.util.zip.ZipFile

def bootJar = new File(basedir, 'target/app-1.0-boot.jar')
def plainJar = new File(basedir, 'target/app-1.0.jar')
def sbomFile = new File(basedir, 'target/classes/META-INF/sbom/application.cdx.json')

// The launch script of the executable jar is still in front of the archive
assert bootJar.newInputStream().withCloseable { new String(it.readNBytes(11)) } == '#!/bin/bash'
assert bootJar.canExecute()

def packed = []
new ZipFile(bootJar).withCloseable { zip ->
    zip.entries().each { if (it.name.startsWith('BOOT-INF/lib/') && it.name.endsWith('.jar')) packed << it.name.substring('BOOT-INF/lib/'.length()) }
}
// Both jars embed the SBOM; the Spring Boot jar says where, as Spring Boot does for an SBOM it packs itself
[bootJar, plainJar].each { jar ->
    new ZipFile(jar).withCloseable { assert it.getInputStream(it.getEntry('META-INF/sbom/application.cdx.json')).bytes == sbomFile.bytes }
}
new JarFile(bootJar).withCloseable {
    assert it.manifest.mainAttributes.getValue('Sbom-Location') == 'META-INF/sbom/application.cdx.json'
    assert it.manifest.mainAttributes.getValue('Sbom-Format') == 'CycloneDX'
}
new JarFile(plainJar).withCloseable { assert it.manifest.mainAttributes.getValue('Sbom-Location') == null }

// The SBOM lists exactly the packed libraries
def sbom = new JsonSlurper().parse(sbomFile)
def listed = sbom.components.collect {
    def classifier = (it.purl =~ /classifier=([^&]+)/)
    it.name + '-' + it.version + (classifier ? '-' + classifier[0][1] : '') + '.jar'
}
assert listed.sort() == packed.sort()

def refs = sbom.components*.'bom-ref'
def starter = { it.startsWith('pkg:maven/org.springframework.boot/spring-boot-starter') }
assert !refs.any(starter)
assert sbom.components.findAll { it.name == 'jffi' }.size() == 2

// A library that is not a dependency of the project is described by its pom
def tools = sbom.components.find { it.name == 'spring-boot-jarmode-tools' }
assert tools.licenses*.license*.id == ['Apache-2.0']
assert tools.description
assert tools.hashes*.alg.contains('SHA-256')

// What depended on a starter depends on what the starter depended on
def rootRef = sbom.metadata.component.'bom-ref'
def root = sbom.dependencies.find { it.ref == rootRef }
assert root.dependsOn.any { it.startsWith('pkg:maven/org.springframework.boot/spring-boot@') }
assert root.dependsOn.contains(tools.'bom-ref')
def known = (refs + rootRef) as Set
assert sbom.dependencies.every { known.contains(it.ref) && (it.dependsOn ?: []).every { known.contains(it) } }
assert sbom.dependencies*.ref as Set == known

assert sbom.metadata.timestamp == '2026-01-01T00:00:00Z'
assert sbom.metadata.manufacturer.name == 'Example, Inc.'
assert sbom.metadata.tools.components*.name == ['sbom-maven-plugin']
assert sbom.metadata.lifecycles == [[phase: 'build']]
assert sbom.metadata.properties.collectEntries { [it.name, it.value] } == ['maven.goal': 'jar', 'cdx:reproducible': 'enabled']
assert sbom.serialNumber.startsWith('urn:uuid:')

// Every library that cyclonedx-maven-plugin lists and the jar packs has a component with all the same fields, and the same dependencies
def reference = new JsonSlurper().parse(new File(basedir, 'target/cyclonedx/application.cdx.json'))
// The order of the hashes does not matter, and a newer SPDX license list gives a known license another link
def comparable = { component ->
    component.collectEntries { key, value ->
        [key, key == 'hashes' ? value as Set : key == 'licenses' ? value.collect { it.license?.id ? [id: it.license.id] : it } : value]
    }
}
def ours = sbom.components.collectEntries { [it.'bom-ref', it] }
def compared = 0
reference.components.each { theirs ->
    if (!starter(theirs.'bom-ref')) {
        assert comparable(ours[theirs.'bom-ref']) == comparable(theirs)
        compared++
    }
}
assert compared == sbom.components.size() - 1
def ourDependencies = sbom.dependencies.collectEntries { [it.ref, (it.dependsOn ?: []) as Set] }
reference.dependencies.each { theirs ->
    def dependsOn = (theirs.dependsOn ?: []) as Set
    if (theirs.ref != rootRef && !starter(theirs.ref) && !dependsOn.any(starter)) {
        assert ourDependencies[theirs.ref] == dependsOn
    }
}
def describe = { it.findAll { key, value -> key != 'manufacturer' } }
assert comparable(describe(sbom.metadata.component)) == comparable(describe(reference.metadata.component))

// The jar still starts
def java = new File(System.getProperty('java.home'), 'bin/java').path
def run = [java, '-jar', bootJar.path].execute()
def output = run.text
assert run.waitFor() == 0
assert output.contains('started')
true
