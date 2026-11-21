// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
import groovy.json.JsonSlurper

def sbomFile = new File(basedir, 'app/target/sbom/application.cdx.json')
def bom = new JsonSlurper().parse(sbomFile)

def lib = bom.components.find { it.purl.startsWith('pkg:maven/org.example.it.common/fonts-lib@') }
assert lib != null

def roboto = bom.components.find { it.name == 'Roboto' }
assert roboto != null
assert roboto.version == '3.009'
assert roboto.purl == 'pkg:generic/roboto@3.009'
assert roboto.copyright == 'Copyright 2011 The Roboto Project Authors'
assert roboto.licenses[0].expression == 'OFL-1.1'
assert roboto.components*.evidence.occurrences.location == [['fonts/roboto/Roboto-Regular.ttf']]

def icons = bom.components.find { it.name == 'Material Icons' }
assert icons != null
assert icons.version == '1.0'
assert icons.purl == 'pkg:generic/material-icons@1.0'
assert icons.licenses[0].expression == 'Apache-2.0'
assert icons.components*.evidence.occurrences.location == [['fonts/custom/Icons-Regular.ttf']]

def libDeps = bom.dependencies.find { it.ref == lib.'bom-ref' }.dependsOn
assert libDeps.containsAll([roboto.'bom-ref', icons.'bom-ref'])

def log = new File(basedir, 'build.log').text
assert log.contains('Checked the 2 files that the SBOM of org.example.it.common:fonts-lib places in the library')
true
