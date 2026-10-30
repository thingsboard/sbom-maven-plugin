def log = new File(basedir, 'build.log').text
assert log.contains('META-INF/sbom/ui.cdx.json not found in')
true
