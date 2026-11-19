// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
def log = new File(basedir, 'build.log').text
assert log.contains('dist/service.exe, which does not exist')
def written = new File(basedir, 'dist').listFiles().findAll { it.name.endsWith('.cdx.json') }
assert written.isEmpty() : "no package SBOM should be written, but found ${written*.name}"
def bundled = new File(basedir, 'target/sbom').listFiles()?.findAll { it.name.endsWith('.bundled.cdx.json') } ?: []
assert bundled.isEmpty() : "no bundled SBOM should be written, but found ${bundled*.name}"
true
