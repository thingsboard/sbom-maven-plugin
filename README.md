# sbom-maven-plugin

Maven plugin that makes the CycloneDX SBOMs of what a Maven build ships:

- `jar` makes the SBOM of a jar that packs its libraries, such as a Spring Boot jar, from the finished jar, and puts it into the jar.
- `metadata` sets who makes and supplies the software and the SBOM, in an SBOM made by another tool.
- `bundled` writes, before the packages are built, the SBOM of what each distribution package bundles besides the application: the components the build declares.
- `package` writes one SBOM per distribution package (`.deb`, `.rpm`, `.zip`), next to the package file: the application SBOM and the bundled SBOM of the package.
- `image` writes the SBOM of every architecture of a pushed Docker image and attaches it to the image: what Syft finds in the image, with the parts we built replaced by our own SBOMs.

ThingsBoard uses it to make the SBOM of every Spring Boot jar it ships, with the npm SBOM of the Angular UI (`ui-ngx`) folded into the SBOM of the server application. The result is one SBOM per shipped artifact, with the npm packages attached to the `ui-ngx` component in the dependency graph.

## jar goal

The goal reads the libraries that the finished jar packs and writes one component for each of them. So the SBOM lists what the jar ships, whatever the packaging added to the dependencies of the project or left out of them: Spring Boot adds `spring-boot-jarmode-tools` by itself and leaves the starters out.

```xml
<plugin>
    <groupId>org.thingsboard</groupId>
    <artifactId>sbom-maven-plugin</artifactId>
    <version>2.0.0</version>
    <executions>
        <execution>
            <goals>
                <goal>jar</goal>
            </goals>
            <configuration>
                <jar>${project.build.directory}/${project.build.finalName}-boot.jar</jar>
                <otherJars>
                    <otherJar>${project.build.directory}/${project.build.finalName}.jar</otherJar>
                </otherJars>
                <libraries>
                    <library>
                        <group>org.springframework.boot</group>
                        <name>spring-boot-jarmode-tools</name>
                    </library>
                </libraries>
                <nestedSboms>
                    <nestedSbom>
                        <library>org.thingsboard:ui-ngx</library>
                    </nestedSbom>
                </nestedSboms>
            </configuration>
        </execution>
    </executions>
</plugin>
```

The goal runs at `package` by default. Declare the plugin after the plugin that packs the jar (`spring-boot-maven-plugin`), so the goal runs after it, and before anything that reads the jar or the SBOM. Maven runs the goals of one plugin together within a phase, so a build that also uses the `package` goal, which runs after the packages are built from the jar, cannot keep both in the `package` phase. Build the jar one phase earlier: bind `maven-jar-plugin:jar` (execution `default-jar`), `spring-boot-maven-plugin:repackage` and this goal to `prepare-package`, in that order in the POM.

| Parameter | Property | Default | Description |
| --- | --- | --- | --- |
| `jar` | `sbom.jar.jar` | `${project.build.directory}/${project.build.finalName}.jar` | The jar that packs the libraries. The build fails when it packs none |
| `libraryDirectory` | `sbom.jar.libraryDirectory` | `BOOT-INF/lib` | The directory of the jar that holds the libraries |
| `sbomFile` | `sbom.jar.sbomFile` | `${project.build.directory}/sbom/application.cdx.json` | Where the SBOM is written. Not in the output directory, where a later build without `clean` would pack it |
| `resource` | `sbom.jar.resource` | `META-INF/sbom/application.cdx.json` | Path of the SBOM inside a jar |
| `otherJars` | | | Other jars of the project that get the same SBOM. One that does not exist is passed over |
| `libraries` | | | Libraries that the packaging adds and that are not Maven dependencies of the project: `group` and `name`. The file in the jar is `<name>-<version>.jar`, where the version starts with a digit or is the `Implementation-Version` of the manifest of the library. Its pom comes from the repositories of the project |
| `nestedSboms` | | | Packed libraries that carry the SBOM of what they bundle: `library` (`groupId:artifactId`), optional `resource` (path of the SBOM inside the library, `META-INF/sbom/<artifactId>.cdx.json` by default) and optional `skip` |
| `projectType` | `sbom.jar.projectType` | `application` | CycloneDX type of the component of the project |
| `manufacturer`, `supplier`, `componentManufacturer` | | | As in the `metadata` goal |
| `timestamp` | `sbom.jar.timestamp` | `${project.build.outputTimestamp}` | As in the `metadata` goal; the time the goal runs when it is not set |
| `skip` | `sbom.jar.skip` | `false` | Skip the SBOM of the jar |

A packed library is a Maven dependency of the project when its file has the name Spring Boot gives that dependency, `<artifactId>-<version>[-<classifier>].jar`, or that name after the group and a `-`, and the same SHA-256 as the file Maven resolved. Any other library must be declared in `libraries`, or the build fails.

The SBOM is CycloneDX 1.6 and has what `cyclonedx-maven-plugin` writes, by the same rules:

- A component has the coordinates of the artifact, its purl with type and classifier, eight hashes of the file, and from the effective pom of the artifact its description, publisher, licenses and links (website, version control, issue tracker, mailing list, build system, distribution). A license is an SPDX id when its name or else its URL is one that SPDX knows, an SPDX expression when it is the only license of the pom and its name is one, such as `EPL-2.0 OR BSD-3-Clause`, and keeps its name and URL when not. A component has the type that the pom of its artifact gives `cyclonedx-maven-plugin` as `projectType`, and is a `library` otherwise.
- The dependency graph is the one Maven resolves, without the test dependencies. A dependency that lost a version conflict is an edge to the version that won. What depended on an artifact that is not packed, such as a starter, depends on what that artifact depended on. Maven's graph can lack a packed dependency, when the version that won a conflict sits under a test dependency. Such a library takes its place from the poms: it depends on the packed libraries that its pom names, and the packed libraries whose pom names it depend on it. A library that nothing depends on, such as one declared in `libraries` or one that no pom names, is a dependency of the project, so every library is reached from it.
- The metadata has the component of the project, described by its pom, this plugin as the tool, the lifecycle phase `build`, the properties `maven.goal` and, for a build with a fixed time, `cdx:reproducible`, and a serial number that is the same for the same project and properties.

A nested SBOM is folded in as follows:

- Its components and their dependency graph are appended.
- Its root (`metadata.component`) is replaced with the library that carries it, so the library depends on the direct dependencies of the nested root.
- Its tools are added to `metadata.tools.components`.

The SBOM is put into each jar at `resource`: an entry that is there is replaced, and one that is not is added at the end of the jar. A Spring Boot jar also gets `Sbom-Location` and `Sbom-Format` in its manifest, as Spring Boot sets them for an SBOM it finds when it packs the jar. Every other entry keeps its compressed bytes, time, attributes and place, and a launch script in front of an executable jar is kept.

The build fails, and no jar is changed, when the jar does not exist or packs no libraries, a packed library is neither a dependency of the project nor declared, a packed library has other content than the file Maven resolved, two packed libraries are the same component, a declared library has no group, the pom of a library cannot be read, the library of a nested SBOM is not `groupId:artifactId` or not a dependency of the project, a nested SBOM is missing, is not CycloneDX 1.6, has a root without direct dependencies or lists its root as a component, a component of a nested SBOM clashes with a different component with the same bom-ref, an organization has no name, the timestamp is not a date and time with an offset, or the result fails schema validation.

## metadata goal

```xml
<execution>
    <id>sbom-metadata</id>
    <goals>
        <goal>metadata</goal>
    </goals>
    <configuration>
        <targetFile>${project.build.directory}/sbom/ui.cdx.json</targetFile>
        <manufacturer>
            <name>ThingsBoard, Inc.</name>
            <urls>
                <url>https://thingsboard.io</url>
            </urls>
            <contacts>
                <contact>
                    <email>security@thingsboard.io</email>
                </contact>
            </contacts>
        </manufacturer>
        <supplier>...</supplier>
        <componentManufacturer>...</componentManufacturer>
    </configuration>
</execution>
```

| Parameter | Sets | Meaning (CycloneDX 1.6) |
| --- | --- | --- |
| `manufacturer` | `metadata.manufacturer` | The organization that created the SBOM |
| `supplier` | `metadata.supplier` | The organization that supplies the software the SBOM describes |
| `componentManufacturer` | `metadata.component.manufacturer` | The organization that created the software the SBOM describes |
| `timestamp` (`sbom.metadata.timestamp`) | `metadata.timestamp` | When the SBOM was made. Default: `${project.build.outputTimestamp}` |

`timestamp` is a date and time with an offset (`2026-01-31T12:00:00Z`) or seconds since 1970, and is written in UTC. By default it is `project.build.outputTimestamp`, the time Maven builds reproducibly with, so set the property to the time of the release when you set the release version. Without it, or with the `1980-02-01T00:00:00Z` that newer Maven versions set by themselves, the timestamp of the SBOM stays as it is. The `package` goal copies the timestamp of the application SBOM, and the `image` goal that of the first component with an `sbom`.

Each of the first three is an organization with a `name`, optional `urls` and optional `contacts` (`name`, `email`, `phone`). Configured fields replace existing values; fields that are not configured are left as they are. `targetFile` (`sbom.metadata.targetFile`) is the SBOM to update and is required; the `jar` goal sets the organizations of its SBOM itself. Also takes `skip` (`sbom.metadata.skip`).

The build fails, and the file is left untouched, when nothing is configured, the timestamp is not a date and time with an offset, an organization has no name, a url is blank, a contact is empty, the SBOM is older than CycloneDX 1.6, the input or the result fails schema validation, or anything other than these fields would change.

## bundled goal

The `bundled` and the `package` goals describe the same packages, so their `name`, `version` and `packages` go into the configuration of the plugin, which both executions share:

```xml
<plugin>
    <groupId>org.thingsboard</groupId>
    <artifactId>sbom-maven-plugin</artifactId>
    <configuration>
        <name>thingsboard</name>
        <packages>
            <package>
                <id>deb</id>
                <file>${project.build.directory}/thingsboard.deb</file>
                <purl>pkg:deb/thingsboard/thingsboard@${project.version}-1?arch=all</purl>
                <skip>false</skip>
            </package>
            <package>
                <id>zip</id>
                <file>${project.build.directory}/thingsboard-windows.zip</file>
                <purl>pkg:generic/thingsboard/thingsboard-windows@${project.version}</purl>
            </package>
        </packages>
    </configuration>
    <executions>
        <execution>
            <id>bundled-sbom</id>
            <goals>
                <goal>bundled</goal>
            </goals>
            <configuration>
                <components>
                    <component>
                        <sbom>${project.basedir}/src/main/sbom/gateway-management-extension.cdx.json</sbom>
                        <file>${project.build.directory}/data/resources/js_extensions/gateway-management-extension.js</file>
                    </component>
                    <component>
                        <type>cryptographic-asset</type>
                        <name>DigiCert Global Root G2</name>
                        <file>${project.build.directory}/data/certs/azure/DigiCertGlobalRootG2.crt.pem</file>
                    </component>
                    <component>
                        <type>application</type>
                        <group>com.sun.winsw</group>
                        <name>winsw</name>
                        <version>2.0.1</version>
                        <purl>pkg:maven/com.sun.winsw/winsw@2.0.1?classifier=bin&amp;type=exe</purl>
                        <license>MIT</license>
                        <file>${project.build.directory}/windows/service.exe</file>
                        <packages>
                            <package>zip</package>
                        </packages>
                    </component>
                </components>
            </configuration>
        </execution>
        <execution>
            <id>package-sbom</id>
            <goals>
                <goal>package</goal>
            </goals>
        </execution>
    </executions>
</plugin>
```

The `image` goal has a `version` parameter too: a `version` for the packages that differs from the project version goes into both executions instead, or the images take it as well.

The `bundled` goal runs at `prepare-package` by default: before the packages are built, once the files of the components are in place. What is made before the packages can then read what they bundle, such as third-party notices that go into them. For each package that is not skipped it writes `<outputDirectory>/<name>-<package id>.bundled.cdx.json`, once every package has been checked, also when the package bundles nothing:

- The root component (`metadata.component`) is `<name>-<package id>-bundled` with the configured `version`; its `bom-ref` is `<name>-<package id>-bundled@<version>`. It depends on every component the package bundles.
- Each bundled component the package contains is added. A file gets its SHA-256 and SHA-512; a directory gets no hashes. A `cryptographic-asset` must point to an X.509 certificate, whose subject, issuer and validity are added as `cryptoProperties`.
- A bundled component with an `sbom` takes everything from that SBOM instead of the configuration: its root becomes the component, and its components and dependencies are added under it. The SBOM must give the SHA-256 of `file`, and it must match the file being packaged, so a file copied without its SBOM, or with an SBOM from another build, fails the build. Its tools are added to `metadata.tools`.
- The SBOM is CycloneDX 1.6. The `serialNumber` is derived from the root and the components.

| Parameter | Property | Default | Description |
| --- | --- | --- | --- |
| `packages` | | required | Packages: `id`, optional `skip`; their `file` and `purl`, which the `package` goal needs, are allowed |
| `components` | | none | Bundled components: `type` (default `library`), `group`, `name`, `version`, `description`, `purl`, `cpe`, `license` (an SPDX license expression such as `MIT` or `EPL-2.0 OR BSD-3-Clause`; the build fails on anything else), `supplier` (`name`, `urls`, `contacts`), `externalReferences` (`type`, one of the [CycloneDX types](https://cyclonedx.org/docs/1.6/json/#components_items_externalReferences_items_type) such as `license`, and `url`), `file`, `sbom` (CycloneDX SBOM of `file`; replaces all the other details), `packages` (ids of the packages that contain it; all when empty) |
| `name` | `sbom.package.name` | `${project.artifactId}` | Name of the package component |
| `version` | `sbom.package.version` | `${project.version}` | Version of the package component |
| `outputDirectory` | `sbom.bundled.directory` | `${project.build.directory}/sbom` | Directory to write the bundled SBOMs to |
| `skip` | `sbom.bundled.skip` | `false` | Skip all packages |

The build fails, and no bundled SBOM is written, when there are no packages, package ids repeat or one is blank, a bundled component has no name, is declared twice, has an `sbom` together with details of its own or without a `file`, sets `installDir` or `bundleDir`, still contains an unresolved `${...}` property, has a supplier without name or with a blank url, has an external reference without a type or a url, has an `sbom` that is invalid, uses another spec version, has components its root does not depend on, or does not match the file's hashes, refers to an unknown package id, points to a missing file or an empty directory, a `cryptographic-asset` is not an X.509 certificate, a `cpe` does not start with `cpe:2.3:` or `cpe:/`, or the result fails schema validation.

## package goal

Configured together with the `bundled` goal: see the example there.

The `package` goal runs at `package` by default. Declare the plugin after the plugins that build the packages, so it runs after them in the same phase. It needs the bundled SBOM of every package that is not skipped, which the `bundled` goal writes; a bundled SBOM of another package, name or version fails the build. The application SBOM must be CycloneDX 1.6, as the bundled SBOMs are. For each package that is not skipped it writes `<package file>.cdx.json` next to the package, once every package has been checked:

- The package is the root component (`metadata.component`): the configured `name`, `version` and `purl`, the SHA-256 and SHA-512 of the package file, and the description, licenses, manufacturer and website of the application.
- The application SBOM's root and all its components and dependencies are kept unchanged; the package depends on the application.
- The components of the bundled SBOM of the package and their dependencies are added, and the package depends on what the root of the bundled SBOM depends on. Components already in the application SBOM with the same `bom-ref` and `purl` are not added twice. Its tools are added to `metadata.tools`.
- `metadata.tools`, `lifecycles`, `manufacturer` and `supplier` are copied from the application SBOM. The `serialNumber` is derived from the package purl and contents.

| Parameter | Property | Default | Description |
| --- | --- | --- | --- |
| `packages` | | required | Packages to describe: `id`, `file`, `purl`, optional `skip` |
| `name` | `sbom.package.name` | `${project.artifactId}` | Name of the package component |
| `version` | `sbom.package.version` | `${project.version}` | Version of the package component |
| `sourceFile` | `sbom.package.sourceFile` | `${project.build.directory}/sbom/application.cdx.json` | Application SBOM to start from: by default the one the `jar` goal writes |
| `bundledDirectory` | `sbom.bundled.directory` | `${project.build.directory}/sbom` | Directory with the bundled SBOMs that the `bundled` goal writes |
| `skip` | `sbom.package.skip` | `false` | Skip all packages |

The build fails, and no package SBOM is written, when package ids repeat, a package has no purl or an invalid one, a package file is missing or empty, a package has no bundled SBOM, or one of another package, name or version, or one with another spec version than the application SBOM, a bundled component clashes with a component already in the SBOM, or the result fails schema validation or loses a dependency path of the application.

## image goal

```xml
<execution>
    <id>image-sbom</id>
    <phase>post-integration-test</phase>
    <goals>
        <goal>image</goal>
    </goals>
    <configuration>
        <repository>thingsboard/tb-node</repository>
        <tags>
            <tag>latest</tag>
            <tag>${project.version}</tag>
        </tags>
        <scanExclude>/usr/share/thingsboard/**</scanExclude>
        <components>
            <component>
                <sbom>${main.dir}/application/target/thingsboard.deb.cdx.json</sbom>
                <file>${project.build.directory}/thingsboard.deb</file>
            </component>
        </components>
    </configuration>
</execution>
```

The `image` goal has no default phase: bind it after the build pushes the image, because it reads the image from the registry. For every architecture of the pushed image it:

1. finds the digest of that architecture's image with `docker buildx imagetools inspect --raw`, for each of the `tags`. Tags that point to the same image share one SBOM;
2. scans the image with `syft scan registry:<repository>@<digest>`, leaving out `scanExclude`;
3. writes the image SBOM to `<outputDirectory>/<namespace>_<name>_<version>_<architecture>_<first 12 digits of the digest>.cdx.json`;
4. attaches the SBOM to that architecture's image as an OCI referrer artifact of type `application/vnd.cyclonedx+json` with `oras attach`, unless `oras discover` finds one there.

Nothing is attached unless the SBOM of every architecture is written. An image that has a CycloneDX SBOM attached already keeps it and gets no second one, so when attaching fails part-way, the images attached so far keep their SBOMs and running the build again attaches the rest.

It needs `docker` with buildx, [`syft`](https://github.com/anchore/syft) and [`oras`](https://oras.land) on the `PATH`, logged in to the registry as for `docker push`. The image must be a multi-architecture one, pushed with `docker buildx build --platform`.

To see what is attached to an image: `oras discover thingsboard/tb-node@sha256:40c3...`.

The result describes the image as a `container` root component (`pkg:docker/<namespace>/<name>@<digest>?arch=<architecture>`, with `&repository_url=<registry>` when the image is not on Docker Hub; version = `version`, SHA-256 = digest) that depends on everything in it:

- Everything the scan found is kept unchanged, except what the bundled components replace. The scan's own root is dropped; the image depends on the scanned components nothing else depends on, and on one component of each dependency cycle nothing outside the cycle depends on.
- Each bundled component is added with its SBOM, as in the `package` goal, and the image depends on it. Its tools are added to `metadata.tools`; `lifecycles`, `manufacturer`, `supplier` and the root's manufacturer come from the first bundled SBOM.
- The `serialNumber` is derived from the image purl, so each architecture's SBOM has its own.

A bundled component with an `sbom` says how its SBOM is checked against the image with exactly one of:

| Anchor | For | Check |
| --- | --- | --- |
| `file` | A package the image installs, e.g. `.deb` | The SBOM must give the SHA-256 of `file`, as in the `package` goal. When its root is a `deb`, `rpm` or `apk` package, the scan must list exactly one installed package with that purl type and name, and with the version of the SBOM's purl; it is replaced by the SBOM's root and keeps the dependencies the scan found (e.g. on the JRE). Exclude the package's install directory from the scan with `scanExclude`: the build fails when the scan lists any component of the SBOM. |
| `installDir` | An npm application installed in the image by `yarn install` | Everything the scan found under the directory must be in the SBOM at the same path (`cdx:npm:package:path`) and version, or be an optional package without a path that matches by purl; it is replaced by the SBOM's component. Every required package must be installed at each of its paths. Optional packages (`scope: optional`) the image does not have are dropped with their dependencies, so platform-specific packages listed for every platform (`yarn-sbom.js --all-platforms`) keep only the ones this architecture installs. The scan's entry for the application's own `package.json` is replaced by the SBOM's root. Do not exclude the directory from the scan. |
| `bundleDir` | Prebuilt files copied into the image, e.g. a web UI bundle | Everything the scan found under the directory must be in the SBOM by purl; it is replaced by the SBOM's component. The SBOM may list more, since bundled code has no files per package. |

Scanned components are claimed by the most specific directory, so a `bundleDir` can sit inside an `installDir`. A component outside every directory stays a component of the scan, even when a bundled SBOM lists the same purl: base images often ship their own copy of a package.

A bundled component without an `sbom`, such as a browser an install script downloads, is added from its configuration as in the `package` goal; `file` is optional.

| Parameter | Property | Default | Description |
| --- | --- | --- | --- |
| `repository` | `sbom.image.repository` | required | `<namespace>/<name>` of the image, without tag. Docker Hub is the registry unless one comes first: `registry.example.com/<namespace>/<name>` |
| `tags` | `sbom.image.tags` | `${project.version}` | Every tag the build pushed; blank tags are ignored |
| `version` | `sbom.image.version` | `${project.version}` | Version of the image component |
| `plainHttp` | `sbom.image.plainHttp` | `false` | Talk to the registry over plain HTTP, for a local test registry |
| `scanExclude` | `sbom.image.scanExclude` | | Glob of the image paths Syft must not scan |
| `outputDirectory` | `sbom.image.outputDirectory` | `${project.build.directory}/sbom` | Where to write the scans and the image SBOMs |
| `components` | | required | Bundled components, as in the `package` goal without `packages`, plus `installDir` and `bundleDir` (absolute paths in the image); `@{architecture}` in a version, purl or cpe stands for the architecture of the image |
| `attach` | `sbom.image.attach` | `true` | Attach the SBOMs to the image; `false` only writes them |
| `docker`, `syft`, `oras` | `sbom.image.docker`, `sbom.image.syft`, `sbom.image.oras` | `docker`, `syft`, `oras` | The executables to run |
| `skip` | `sbom.image.skip` | `false` | Skip the image SBOMs |

The build fails, and nothing is attached, when the repository is not `<namespace>/<name>` after the optional registry, no tag is configured, `docker`, `syft` or `oras` is missing or fails (the message of the tool is reported), a tag is not a multi-architecture image with Linux images, an architecture is not lowercase letters and digits, the version is blank, no components are configured, a component has no name, is declared twice, has an `sbom` together with details of its own, sets `packages`, or has a supplier without name or with a blank url, has an external reference without a type or a url, a component with an `sbom` sets none or more than one of `file`, `installDir` and `bundleDir`, a component without an `sbom` sets a directory, a directory is not absolute or ends with `/`, a value still contains an unresolved `${...}` property, the scan does not list a `file` package exactly once or lists it with another version, the scan lists a component of a `file` component's SBOM, the image has a component without a purl under a directory, or a package that the SBOM does not list or lists with another version, a required package is not installed at its path or has no path, components clash, the result fails schema validation, or a component is not reachable from the image.

## Upgrading to 3.0.0

The `package` goal no longer takes `components`. Move them to an execution of the `bundled` goal, and put `name`, `version` and `packages` into the configuration of the plugin, as in the [bundled goal](#bundled-goal) example. A `package` execution that still has `components` fails the build. The application SBOM of the `package` goal must be CycloneDX 1.6.

## Skipping

`-Dsbom.skip=true` skips every goal of the plugin, whatever the `skip` of a goal says. Skip the `bundled` and the `package` goals together, with `sbom.skip`: the `package` goal fails without the bundled SBOMs. A build that makes SBOMs only on request sets the `sbom.skip` property to `true` in the POM and runs with `-Dsbom.skip=false`, or in a profile that sets it to `false`, when it needs them.

## Building

```
./mvnw verify
```

`./mvnw test` runs the unit tests, which need no Docker. `verify` also runs two kinds of integration tests:

- `*IT` classes in `src/test/java`, run by Failsafe, validate jar, package and image SBOMs with the official `cyclonedx-cli` in Docker (Testcontainers). They are skipped when Docker is not available, and with `-DskipITs`. `RegistryImageIT` runs what the `image` goal does with the real `docker buildx`, `syft` and `oras` against a registry in Docker: it is also skipped when `syft` or `oras` is not installed or Docker cannot push a two-architecture image, except in CI, which installs the versions pinned in `.github/workflows/build.yml`.
- The projects in `src/it`, run by Invoker, build small projects with the plugin. The `jar` project also runs `cyclonedx-maven-plugin` and requires the same fields and dependencies for every library that both list. The `image` goal runs there with the stand-ins for `docker`, `syft` and `oras` in `src/it/stubs`. They are skipped with `-Dinvoker.skip`.

## Releasing

Releases are deployed to `https://repo.thingsboard.io/artifactory/libs-release-public` by the release manager, whose `~/.m2/settings.xml` holds the credentials of the `thingsboard-repo-deploy` server. From an up-to-date `main`:

```
./release.sh 1.0.0 1.0.1-SNAPSHOT
```

Every release is marked twice on GitHub, and neither mark is ever deleted or moved: the tag `v1.0.0` on the commit of the release, and the branch `release/1.0.0` on the commit after it, which starts the next development version.

The next development version is optional and defaults to the next patch version. The script stops at the first failure, and:

1. Runs `release:prepare` on a new local `release/1.0.0` branch, without pushing. It commits `1.0.0`, with `project.build.outputTimestamp` set to the current time, tags that commit `v1.0.0`, then commits `1.0.1-SNAPSHOT`.
2. Pushes the branch as `chore/release-1.0.0`, opens a PR from it and waits for its checks.
3. Merges the PR once the checks pass. `main` takes only merge commits, so the tagged commit stays in its history; GitHub then deletes `chore/release-1.0.0`.
4. Pushes the tag and the `release/1.0.0` branch, then runs `release:perform`: builds the tag in `target/checkout` and deploys it.
5. Creates the GitHub Release `v1.0.0` with generated notes and the plugin jar.

The release builds skip the tests, since CI has run them on the PR.

If the script stops, its last message says what to do:

- **Start over** when it stops before the PR is merged: nothing is published yet. Close the PR if one was opened, run `git switch --discard-changes main`, then delete the local `release/1.0.0` branch and `v1.0.0` tag, and the `chore/release-1.0.0` branch on GitHub.
- **Finish the release by hand** when it stops after the PR is merged. From the same clone, run the steps that have not run yet:

  ```
  git fetch origin main && git merge-base --is-ancestor release/1.0.0 origin/main   # must succeed: else push nothing, start over
  git push origin v1.0.0 release/1.0.0
  ./mvnw release:perform
  gh release create v1.0.0 --verify-tag --generate-notes --title v1.0.0 target/checkout/target/sbom-maven-plugin-1.0.0.jar
  git switch main && git pull --ff-only && git branch --delete release/1.0.0
  ```

  Once `release:perform` has deployed, the version is in Artifactory and cannot be deployed again.

Every commit sets `project.build.outputTimestamp`, so any of them, release tags included, can be rebuilt into identical artifacts.

## License

Apache License 2.0
