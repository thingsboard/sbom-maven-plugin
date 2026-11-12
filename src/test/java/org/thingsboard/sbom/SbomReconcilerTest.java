// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
package org.thingsboard.sbom;

import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;
import org.thingsboard.sbom.JarLibraries.Library;

import java.util.List;
import java.util.Map;
import java.util.Optional;
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
    private static final Function<Library, Optional<ObjectNode>> NONE = library -> Optional.empty();

    @Test
    void anSbomThatListsExactlyThePackedLibrariesIsNotChanged() {
        ObjectNode bom = source();

        SbomReconciler.Result result = SbomReconciler.reconcile(bom, packed(), NONE);

        assertThat(result.changed()).isFalse();
        assertThat(result.bom().get("components")).isEqualTo(bom.get("components"));
    }

    @Test
    void aComponentThatIsNotPackedIsRemovedAndItsDependenciesMoveToWhatDependedOnIt() {
        SbomReconciler.Result result = SbomReconciler.reconcile(source(), List.of(library("core-1.0.jar", "b"), library("ffi-2.0-native.jar", "c")),
                NONE);

        assertThat(result.removed()).containsExactly(STARTER);
        assertThat(SbomChecks.componentRefs(result.bom())).containsExactlyInAnyOrder(CORE, NATIVE, NPM);
        assertThat(graph(result.bom()).get("app")).containsExactlyInAnyOrder(CORE, NPM);
        assertThat(graph(result.bom())).doesNotContainKey(STARTER);
    }

    @Test
    void aPackedLibraryThatIsNotListedIsAddedUnderWhatDependsOnItsSibling() {
        SbomReconciler.Result result = SbomReconciler.reconcile(source(), packed(library("ffi-2.0.jar", "d")),
                library -> Optional.of(component(PLAIN, "ffi", "2.0")));

        assertThat(result.added()).containsExactly(PLAIN);
        assertThat(graph(result.bom()).get(CORE)).containsExactlyInAnyOrder(NATIVE, PLAIN);
        assertThat(result.bom().get("components").findValuesAsText("content")).contains("d".repeat(64));
    }

    @Test
    void aPackedLibraryWithoutSiblingIsAddedUnderTheRoot() {
        String tools = "pkg:maven/org.example/tools@3.0?type=jar";

        SbomReconciler.Result result = SbomReconciler.reconcile(source(), packed(library("tools-3.0.jar", "e")),
                library -> Optional.of(component(tools, "tools", "3.0")));

        assertThat(graph(result.bom()).get("app")).contains(tools);
    }

    @Test
    void aPackedLibraryThatNothingIdentifiesIsRefused() {
        assertThatThrownBy(() -> SbomReconciler.reconcile(source(), packed(library("mystery-9.jar", "f")), NONE))
                .isInstanceOf(SbomException.class).hasMessageContaining("mystery-9.jar");
    }

    @Test
    void aComponentMatchedByFileNameGetsTheHashesOfThePackedFile() {
        SbomReconciler.Result result = SbomReconciler.reconcile(source(), List.of(library("starter-1.0.jar", "a"), library("core-1.0.jar", "9"),
                library("ffi-2.0-native.jar", "c")), NONE);

        assertThat(result.rehashed()).containsExactly(CORE);
        assertThat(result.added()).isEmpty();
        assertThat(result.removed()).isEmpty();
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
