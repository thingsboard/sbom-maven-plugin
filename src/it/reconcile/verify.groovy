// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
import groovy.json.JsonSlurper

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
// Both jars embed the corrected SBOM; Spring Boot keeps META-INF/sbom at the root of the jar it packs
[bootJar, plainJar].each { jar ->
    new ZipFile(jar).withCloseable { assert it.getInputStream(it.getEntry('META-INF/sbom/application.cdx.json')).bytes == sbomFile.bytes }
}

// The SBOM lists exactly the packed libraries
def sbom = new JsonSlurper().parse(sbomFile)
def listed = sbom.components.findAll { it.purl.startsWith('pkg:maven/') }.collect {
    def classifier = (it.purl =~ /classifier=([^&]+)/)
    it.name + '-' + it.version + (classifier ? '-' + classifier[0][1] : '') + '.jar'
}
assert listed.sort() == packed.sort()

def refs = sbom.components*.'bom-ref'
assert refs.any { it.startsWith('pkg:maven/org.springframework.boot/spring-boot-jarmode-tools@') }
assert !refs.any { it.startsWith('pkg:maven/org.springframework.boot/spring-boot-starter@') }
assert !refs.any { it.startsWith('pkg:maven/org.springframework.boot/spring-boot-starter-logging@') }
def jffi = sbom.components.findAll { it.name == 'jffi' }
assert jffi.size() == 2
assert jffi*.licenses.unique().size() == 1
assert jffi*.hashes.every { it*.alg.contains('SHA-256') }

// What depended on a starter depends on what the starter depended on
def root = sbom.dependencies.find { it.ref == sbom.metadata.component.'bom-ref' }
assert root.dependsOn.any { it.startsWith('pkg:maven/org.springframework.boot/spring-boot@') }
assert root.dependsOn.any { it.startsWith('pkg:maven/org.springframework.boot/spring-boot-jarmode-tools@') }
def known = (refs + sbom.metadata.component.'bom-ref') as Set
assert sbom.dependencies.every { known.contains(it.ref) && (it.dependsOn ?: []).every { known.contains(it) } }

// The jar still starts
def java = new File(System.getProperty('java.home'), 'bin/java').path
def run = [java, '-jar', bootJar.path].execute()
def output = run.text
assert run.waitFor() == 0
assert output.contains('started')

def log = new File(basedir, 'build.log').text
assert log.contains('Added to the SBOM, packed but not listed: pkg:maven/org.springframework.boot/spring-boot-jarmode-tools@')
assert log.contains('Removed from the SBOM, listed but not packed: pkg:maven/org.springframework.boot/spring-boot-starter@')
true
