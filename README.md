# sbom-maven-plugin

Maven plugin that merges a CycloneDX SBOM embedded in a dependency into the project's own CycloneDX SBOM.

ThingsBoard uses it to fold the npm SBOM of the Angular UI (`ui-ngx`, generated with `cyclonedx-npm`) into the Maven SBOM of the server application (generated with `cyclonedx-maven-plugin`). The result is one SBOM per shipped artifact, with the npm packages attached to the `ui-ngx` component in the dependency graph.

## Usage

```xml
<plugin>
    <groupId>org.thingsboard</groupId>
    <artifactId>sbom-maven-plugin</artifactId>
    <version>1.0.0</version>
    <executions>
        <execution>
            <goals>
                <goal>merge</goal>
            </goals>
            <configuration>
                <host>org.thingsboard:ui-ngx</host>
            </configuration>
        </execution>
    </executions>
</plugin>
```

The `merge` goal runs at `process-resources` by default, after `cyclonedx-maven-plugin:makeBom` bound to `generate-resources`.

| Parameter | Property | Default | Description |
| --- | --- | --- | --- |
| `host` | `sbom.merge.host` | required | `groupId:artifactId` of the runtime dependency that carries the nested SBOM |
| `resource` | `sbom.merge.resource` | `META-INF/sbom/<artifactId>.cdx.json` | Path of the nested SBOM inside the host jar or classes directory |
| `targetFile` | `sbom.merge.targetFile` | `${project.build.outputDirectory}/META-INF/sbom/application.cdx.json` | SBOM to merge into, rewritten in place |
| `skip` | `sbom.merge.skip` | `false` | Skip the merge |

## What the merge does

- Appends the nested components and their dependency graph to the target SBOM.
- Replaces the nested SBOM's root (`metadata.component`) with the host component, so the host depends on the nested root's direct dependencies.
- Adds the nested SBOM's tools to `metadata.tools.components`.
- Keeps the target's `serialNumber`, `version` and `metadata.component`.

## Checks

The build fails, and the target file is left untouched, when any of these does not hold:

- Both inputs are CycloneDX JSON with the same `specVersion` and pass schema validation (`cyclonedx-core-java`).
- Both inputs have unique bom-refs and every dependency reference resolves.
- The target has exactly one component whose purl starts with `pkg:maven/<groupId>/<artifactId>@`.
- The nested root has direct dependencies and is not itself listed as a component.
- A bom-ref present in both inputs belongs to identical components.
- The merged SBOM passes schema validation, keeps the target's identity, contains exactly the union of both inputs' components, and every nested component is reachable from the host.

## Building

```
mvn verify
```

Unit tests validate merged SBOMs with the official `cyclonedx-cli` in Docker (Testcontainers); they are skipped when Docker is not available. Integration tests in `src/it` run the plugin together with `cyclonedx-maven-plugin` on small multi-module projects.

## License

Apache License 2.0
