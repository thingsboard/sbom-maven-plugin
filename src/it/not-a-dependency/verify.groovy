// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
def log = new File(basedir, 'build.log').text
assert log.contains('org.example.it:ui is not a runtime dependency of org.example.it:app:jar:1.0')
true
