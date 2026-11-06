def log = new File(basedir, 'build.log').text
assert log.contains('dist/missing.deb does not exist')
true
