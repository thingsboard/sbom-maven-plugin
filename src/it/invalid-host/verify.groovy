def log = new File(basedir, 'build.log').text
assert log.contains("host must be groupId:artifactId, got 'ui'")
true
