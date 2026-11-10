// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
import groovy.json.JsonSlurper

def bom = new JsonSlurper().parse(new File(basedir, 'app/target/classes/META-INF/sbom/application.cdx.json'))
assert bom.components.every { !it.purl.startsWith('pkg:npm/') }
def log = new File(basedir, 'build.log').text
assert log.contains('Skipping SBOM merge')
assert !log.contains('Merged ')
true
