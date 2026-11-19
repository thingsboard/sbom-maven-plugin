// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
def log = new File(basedir, 'build.log').text
assert log.contains('The package goal no longer takes components: move <components> from this execution to an execution of the bundled goal')
true
