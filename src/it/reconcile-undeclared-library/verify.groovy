// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
def log = new File(basedir, 'build.log').text
assert log =~ /The jar packs libraries that the SBOM does not list and that are not Maven dependencies of the project: spring-boot-jarmode-tools-[0-9.]+\.jar/
assert log.contains('Declare each of them in the libraries parameter of the goal')
true
