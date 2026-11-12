// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
package org.thingsboard.sbom;

import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;
import org.thingsboard.sbom.JarLibraries.Library;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.thingsboard.sbom.Boms.bom;
import static org.thingsboard.sbom.Boms.dependency;
import static org.thingsboard.sbom.Boms.graph;

class SbomReconcilerTest {

    private static final String STARTER = "pkg:maven/org.example/starter@1.0?type=jar";
    private static final String CORE = "pkg:maven/org.example/core@1.0?type=jar";
    private static final String NATIVE = "pkg:maven/org.example/ffi@2.0?classifier=native&type=jar";
    private static final String PLAIN = "pkg:maven/org.example/ffi@2.0?type=jar";
    private static final String NPM = "pkg:npm/left-pad@1.0.0";
    private static final Set<String> JAR_TYPES = Set.of("jar", "test-jar");
    private static final PackedLibrary TOOLS = new PackedLibrary("org.example", "tools", "Tools of the packaging", "Apache-2.0");
    private static final Function<Library, Optional<ObjectNode>> NONE = library -> Optional.empty();

    @Test
    void anSbomThatListsExactlyThePackedLibrariesIsNotChanged() {
        ObjectNode bom = source();

        SbomReconciler.Result result = SbomReconciler.reconcile(bom, packed(), JAR_TYPES, NONE);

        assertThat(result.changed()).isFalse();
        assertThat(result.bom().get("components")).isEqualTo(bom.get("components"));
    }

    @Test
    void aComponentThatIsNotPackedIsRemovedAndItsDependenciesMoveToWhatDependedOnIt() {
        SbomReconciler.Result result = SbomReconciler.reconcile(source(), List.of(library("core-1.0.jar", "b"), library("ffi-2.0-native.jar", "c")), JAR_TYPES,
                NONE);

        assertThat(result.removed()).containsExactly(STARTER);
        assertThat(SbomChecks.componentRefs(result.bom())).containsExactlyInAnyOrder(CORE, NATIVE, NPM);
        assertThat(graph(result.bom()).get("app")).containsExactlyInAnyOrder(CORE, NPM);
        assertThat(graph(result.bom())).doesNotContainKey(STARTER);
    }

    @Test
    void componentsThatAreNotPackedAndDependOnEachOtherAreRemovedTogether() {
        ObjectNode bom = bom("1.6", "app");
        component(bom, STARTER, "starter", "1.0", "a");
        component(bom, PLAIN, "ffi", "2.0", "d");
        component(bom, CORE, "core", "1.0", "b");
        dependency(bom, "app", STARTER);
        dependency(bom, STARTER, PLAIN, STARTER);
        dependency(bom, PLAIN, STARTER, CORE);
        dependency(bom, CORE);

        SbomReconciler.Result result = SbomReconciler.reconcile(bom, List.of(library("core-1.0.jar", "b")), JAR_TYPES, NONE);

        assertThat(result.removed()).containsExactly(STARTER, PLAIN);
        assertThat(graph(result.bom())).containsOnlyKeys("app", CORE);
        assertThat(graph(result.bom()).get("app")).containsExactly(CORE);
    }

    @Test
    void twoLibrariesWithTheSameBytesKeepTheirOwnComponents() {
        ObjectNode bom = bom("1.6", "app");
        component(bom, STARTER, "starter", "1.0", "a");
        component(bom, CORE, "core", "1.0", "a");
        dependency(bom, "app", CORE, STARTER);
        dependency(bom, CORE);
        dependency(bom, STARTER);

        // core-1.0.jar comes first and has the hash that the first component, the starter, has too
        SbomReconciler.Result result = SbomReconciler.reconcile(bom, List.of(library("core-1.0.jar", "a"), library("starter-1.0.jar", "a")), JAR_TYPES, NONE);

        assertThat(result.changed()).isFalse();
    }

    @Test
    void aComponentOfAnotherTypeWhoseFileIsAJarIsCompared() {
        String tests = "pkg:maven/org.example/core@1.0?classifier=tests&type=test-jar";
        ObjectNode bom = source();
        component(bom, tests, "core", "1.0", "d");
        dependency(bom, tests);

        SbomReconciler.Result packed = SbomReconciler.reconcile(bom, packed(library("core-1.0-tests.jar", "d")), JAR_TYPES, NONE);
        SbomReconciler.Result notPacked = SbomReconciler.reconcile(bom, packed(), JAR_TYPES, NONE);

        assertThat(packed.changed()).isFalse();
        assertThat(notPacked.removed()).containsExactly(tests);
    }

    @Test
    void aPackedLibraryThatIsNotListedIsAddedUnderWhatDependsOnItsSibling() {
        SbomReconciler.Result result = SbomReconciler.reconcile(source(), packed(library("ffi-2.0.jar", "d")), JAR_TYPES,
                library -> Optional.of(component(PLAIN, "ffi", "2.0")));

        assertThat(result.added()).containsExactly(PLAIN);
        assertThat(graph(result.bom()).get(CORE)).containsExactlyInAnyOrder(NATIVE, PLAIN);
        assertThat(result.bom().get("components").findValuesAsText("content")).contains("d".repeat(64));
    }

    @Test
    void aPackedLibraryWithoutSiblingIsAddedUnderTheRoot() {
        String tools = "pkg:maven/org.example/tools@3.0?type=jar";

        SbomReconciler.Result result = SbomReconciler.reconcile(source(), packed(library("tools-3.0.jar", "e")), JAR_TYPES,
                library -> Optional.of(component(tools, "tools", "3.0")));

        assertThat(graph(result.bom()).get("app")).contains(tools);
    }

    @Test
    void aPackedLibraryThatNothingIdentifiesIsRefused() {
        assertThatThrownBy(() -> SbomReconciler.reconcile(source(), packed(library("mystery-9.jar", "f")), JAR_TYPES, NONE))
                .isInstanceOf(SbomException.class).hasMessageContaining("mystery-9.jar");
    }

    @Test
    void aComponentMatchedByFileNameGetsTheHashesOfThePackedFile() {
        SbomReconciler.Result result = SbomReconciler.reconcile(source(), List.of(library("starter-1.0.jar", "a"), library("core-1.0.jar", "9"),
                library("ffi-2.0-native.jar", "c")), JAR_TYPES, NONE);

        assertThat(result.rehashed()).containsExactly(CORE);
        assertThat(result.added()).isEmpty();
        assertThat(result.removed()).isEmpty();
    }

    @Test
    void aDeclaredLibraryTakesTheVersionItStatesItself() {
        ObjectNode component = SbomReconciler.declared(List.of(TOOLS), "tools-3.5.8.jar", () -> "3.5.8").orElseThrow();

        assertThat(component.get("purl").asText()).isEqualTo("pkg:maven/org.example/tools@3.5.8?type=jar");
        assertThat(component.get("bom-ref")).isEqualTo(component.get("purl"));
        assertThat(component.get("description").asText()).isEqualTo("Tools of the packaging");
        assertThat(component.get("licenses").get(0).get("expression").asText()).isEqualTo("Apache-2.0");
    }

    @Test
    void aDeclaredLibraryThatStatesNoVersionTakesItFromTheFileName() {
        ObjectNode component = SbomReconciler.declared(List.of(TOOLS), "tools-3.5.8.jar", () -> null).orElseThrow();

        assertThat(component.get("version").asText()).isEqualTo("3.5.8");
    }

    @Test
    void aDeclaredNameThatIsOnlyTheStartOfTheFileNameDoesNotMatch() {
        assertThat(SbomReconciler.declared(List.of(TOOLS), "tools-extra-3.5.8.jar", () -> "3.5.8")).isEmpty();
    }

    @Test
    void theDeclarationWhoseNameAndVersionGiveTheFileNameIsTheOneTaken() {
        PackedLibrary longer = new PackedLibrary("org.example", "tools-extra", null, null);

        ObjectNode component = SbomReconciler.declared(List.of(TOOLS, longer), "tools-extra-3.5.8.jar", () -> "3.5.8").orElseThrow();

        assertThat(component.get("name").asText()).isEqualTo("tools-extra");
    }

    @Test
    void aLibraryThatIsNotDeclaredDoesNotAskForItsVersion() {
        assertThat(SbomReconciler.declared(List.of(TOOLS), "other-1.0.jar", () -> {
            throw new AssertionError("The manifest is read only for a library that a declaration may match");
        })).isEmpty();
    }

    @Test
    void aDeclaredLibraryWithoutGroupIsRefused() {
        PackedLibrary noGroup = new PackedLibrary(null, "tools", null, null);

        assertThatThrownBy(() -> SbomReconciler.declared(List.of(noGroup), "tools-3.5.8.jar", () -> "3.5.8"))
                .isInstanceOf(SbomException.class).hasMessageContaining("tools has no group");
    }

    private static ObjectNode source() {
        ObjectNode bom = bom("1.6", "app");
        component(bom, STARTER, "starter", "1.0", "a");
        component(bom, CORE, "core", "1.0", "b");
        component(bom, NATIVE, "ffi", "2.0", "c");
        Boms.component(bom, NPM, NPM);
        dependency(bom, "app", STARTER, NPM);
        dependency(bom, STARTER, CORE);
        dependency(bom, CORE, NATIVE);
        dependency(bom, NATIVE);
        dependency(bom, NPM);
        return bom;
    }

    /**
     * The libraries that {@link #source()} lists, and then {@code more}.
     */
    private static List<Library> packed(Library... more) {
        return Stream.concat(Stream.of(library("starter-1.0.jar", "a"), library("core-1.0.jar", "b"), library("ffi-2.0-native.jar", "c")),
                Stream.of(more)).toList();
    }

    private static void component(ObjectNode bom, String purl, String name, String version, String hashDigit) {
        ObjectNode component = Boms.component(bom, purl, purl).put("group", "org.example").put("name", name).put("version", version);
        component.putArray("hashes").addObject().put("alg", "SHA-256").put("content", hashDigit.repeat(64));
    }

    private static ObjectNode component(String purl, String name, String version) {
        return Boms.MAPPER.createObjectNode().put("type", "library").put("bom-ref", purl).put("group", "org.example").put("name", name)
                .put("version", version).put("purl", purl);
    }

    private static Library library(String fileName, String hashDigit) {
        return new Library(fileName, Map.of("SHA-256", hashDigit.repeat(64)));
    }

}
