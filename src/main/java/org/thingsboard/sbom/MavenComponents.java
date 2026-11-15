// SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
// SPDX-License-Identifier: Apache-2.0
package org.thingsboard.sbom;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.DefaultArtifact;
import org.apache.maven.artifact.handler.manager.ArtifactHandlerManager;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.model.MailingList;
import org.apache.maven.model.building.ModelBuildingRequest;
import org.apache.maven.plugin.descriptor.PluginDescriptor;
import org.apache.maven.project.DefaultProjectBuildingRequest;
import org.apache.maven.project.MavenProject;
import org.apache.maven.project.ProjectBuilder;
import org.apache.maven.project.ProjectBuildingException;
import org.apache.maven.project.ProjectBuildingRequest;
import org.codehaus.plexus.util.xml.Xpp3Dom;
import org.cyclonedx.Version;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.ExternalReference;
import org.cyclonedx.model.Hash;
import org.cyclonedx.model.License;
import org.cyclonedx.model.LicenseChoice;
import org.cyclonedx.model.LicenseItem;
import org.cyclonedx.util.LicenseResolver;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Makes CycloneDX components of Maven artifacts: the coordinates and hashes of the artifact, and what its effective pom
 * says about it. A component has the fields that {@code cyclonedx-maven-plugin} gives it, by the same rules, except that
 * the old address of a license page of the Open Source Initiative is known too.
 */
final class MavenComponents {
    static final Version SPEC_VERSION = Version.VERSION_16;

    private static final Pattern OSI_OLD_URL = Pattern.compile("https?://(?:www\\.)?opensource\\.org/licenses/([^/]+?)(?:\\.php|\\.html|/)?", Pattern.CASE_INSENSITIVE);

    private static final String OR_LATER = "-or-later";
    private static final String CYCLONEDX_PLUGIN = "org.cyclonedx:cyclonedx-maven-plugin";

    private final MavenSession session;
    private final ProjectBuilder projectBuilder;
    private final ArtifactHandlerManager artifactHandlerManager;
    private final MavenProject project;
    private final Map<String, Pom> poms = new LinkedHashMap<>();

    /**
     * What a pom says about the place of its library among the others: which artifact it is, without the version, and
     * which artifacts it needs to run.
     */
    record Pom(String coordinates, Set<String> dependsOn) {}

    /**
     * @param project the project whose repositories the poms come from
     */
    MavenComponents(MavenSession session, MavenProject project, ProjectBuilder projectBuilder, ArtifactHandlerManager artifactHandlerManager) {
        this.session = session;
        this.project = project;
        this.projectBuilder = projectBuilder;
        this.artifactHandlerManager = artifactHandlerManager;
    }

    /**
     * The component of a dependency of the project.
     */
    Component library(Artifact artifact) {
        Component component = library(artifact.getGroupId(), artifact.getArtifactId(), artifact.getBaseVersion(), artifact.getClassifier(), artifact.getType(), artifact.getVersion());
        component.setScope(artifact.isOptional() ? Component.Scope.OPTIONAL : Component.Scope.REQUIRED);
        return component;
    }

    /**
     * The component of a jar that is not a dependency of the project; its pom comes from the repositories of the project.
     */
    Component library(String group, String name, String version) {
        return library(group, name, version, null, "jar", version);
    }

    private Component library(String group, String name, String baseVersion, String classifier, String type, String version) {
        Component component = new Component();
        component.setType(Component.Type.LIBRARY);
        component.setGroup(group);
        component.setName(name);
        component.setVersion(baseVersion);
        component.setScope(Component.Scope.REQUIRED);
        component.setPurl(purl(group, name, baseVersion, type, classifier));
        component.setBomRef(component.getPurl());
        try {
            MavenProject pom = effectiveProject(group, name, version);
            // As cyclonedx-maven-plugin does: a project that states the type of its component there is of that type
            if (pom.getPlugin(CYCLONEDX_PLUGIN) != null && pom.getPlugin(CYCLONEDX_PLUGIN).getConfiguration() instanceof Xpp3Dom configuration
                    && configuration.getChild("projectType") != null) {
                component.setType(componentType(configuration.getChild("projectType").getValue()));
            }
            describe(pom, component);
            poms.put(component.getBomRef(), new Pom(coordinates(group, name, classifier, type), pom.getDependencies().stream()
                    .filter(dependency -> !Artifact.SCOPE_TEST.equals(dependency.getScope()) && !Artifact.SCOPE_PROVIDED.equals(dependency.getScope()))
                    .map(dependency -> coordinates(dependency.getGroupId(), dependency.getArtifactId(), dependency.getClassifier(), dependency.getType()))
                    .collect(Collectors.toSet())));
        } catch (ProjectBuildingException e) {
            throw new SbomException("The pom of " + component.getPurl() + " could not be read, so the SBOM cannot give its license: " + e.getMessage(), e);
        }
        return component;
    }

    /**
     * What the poms of the libraries made so far say, by the bom-ref of the library.
     */
    Map<String, Pom> poms() {
        return poms;
    }

    private static String coordinates(String group, String name, String classifier, String type) {
        return group + ":" + name + ":" + (classifier == null ? "" : classifier) + ":" + (type == null || type.isEmpty() ? "jar" : type);
    }

    /**
     * The component of the project itself: the root of its SBOM.
     */
    Component root(MavenProject project, String type) {
        Component component = new Component();
        component.setType(componentType(type));
        component.setGroup(project.getGroupId());
        component.setName(project.getArtifactId());
        component.setVersion(project.getVersion());
        Artifact artifact = project.getArtifact();
        component.setPurl(purl(artifact.getGroupId(), artifact.getArtifactId(), artifact.getBaseVersion(), artifact.getType(), artifact.getClassifier()));
        component.setBomRef(component.getPurl());
        describe(project, component);
        return component;
    }

    /**
     * The component of this plugin, as the tool that made the SBOM.
     */
    static Component tool(PluginDescriptor plugin) {
        Component component = new Component();
        component.setType(Component.Type.LIBRARY);
        component.setGroup(plugin.getGroupId());
        component.setName(plugin.getArtifactId());
        component.setVersion(plugin.getVersion());
        component.setDescription(plugin.getName());
        Artifact artifact = plugin.getPluginArtifact();
        if (artifact != null && artifact.getFile() != null && artifact.getFile().isFile()) {
            component.setHashes(hashes(SbomFiles.hashes(artifact.getFile().toPath(), SbomFiles.LIBRARY_HASH_ALGORITHMS)));
        }
        return component;
    }

    static List<Hash> hashes(Map<String, String> hashes) {
        return hashes.entrySet().stream().map(hash -> new Hash(hash.getKey(), hash.getValue())).toList();
    }

    static String purl(String group, String name, String version, String type, String classifier) {
        TreeMap<String, String> qualifiers = new TreeMap<>();
        if (type != null && !type.isEmpty()) {
            qualifiers.put("type", type);
        }
        if (classifier != null && !classifier.isEmpty()) {
            qualifiers.put("classifier", classifier);
        }
        try {
            return new PackageURL(PackageURL.StandardTypes.MAVEN, group, name, version, qualifiers.isEmpty() ? null : qualifiers, null).canonicalize();
        } catch (MalformedPackageURLException e) {
            throw new SbomException("No purl can be made for " + group + ":" + name + ":" + version, e);
        }
    }

    private MavenProject effectiveProject(String group, String name, String version) throws ProjectBuildingException {
        Artifact pom = new DefaultArtifact(group, name, version, null, "pom", null, artifactHandlerManager.getArtifactHandler("pom"));
        ProjectBuildingRequest request = new DefaultProjectBuildingRequest(session.getProjectBuildingRequest());
        request.setValidationLevel(ModelBuildingRequest.VALIDATION_LEVEL_MINIMAL);
        request.setProcessPlugins(false);
        request.setRemoteRepositories(project.getRemoteArtifactRepositories());
        request.setResolveDependencies(false);
        return projectBuilder.build(pom, request).getProject();
    }

    private static void describe(MavenProject project, Component component) {
        if (project.getOrganization() != null) {
            component.setPublisher(project.getOrganization().getName());
        }
        component.setDescription(project.getDescription());
        if (project.getLicenses() != null && project.getLicenses().stream().anyMatch(license -> !isBlank(license.getName()) || !isBlank(license.getUrl()))) {
            component.setLicenses(licenses(project.getLicenses()));
        }
        addReference(component, ExternalReference.Type.WEBSITE, project.getUrl());
        if (project.getCiManagement() != null) {
            addReference(component, ExternalReference.Type.BUILD_SYSTEM, project.getCiManagement().getUrl());
        }
        if (project.getDistributionManagement() != null) {
            addReference(component, ExternalReference.Type.DISTRIBUTION, project.getDistributionManagement().getDownloadUrl());
            if (project.getDistributionManagement().getRepository() != null) {
                addReference(component, ExternalReference.Type.DISTRIBUTION_INTAKE, project.getDistributionManagement().getRepository().getUrl());
            }
        }
        if (project.getIssueManagement() != null) {
            addReference(component, ExternalReference.Type.ISSUE_TRACKER, project.getIssueManagement().getUrl());
        }
        if (project.getMailingLists() != null) {
            for (MailingList list : project.getMailingLists()) {
                addReference(component, ExternalReference.Type.MAILING_LIST, list.getArchive() != null ? list.getArchive() : list.getSubscribe());
            }
        }
        if (project.getScm() != null) {
            addReference(component, ExternalReference.Type.VCS, project.getScm().getUrl());
        }
    }

    /**
     * A license of the pom becomes an SPDX id when its name or else its URL is one that SPDX knows, and keeps its name and URL when not.
     */
    static LicenseChoice licenses(List<org.apache.maven.model.License> pomLicenses) {
        LicenseChoice choice = new LicenseChoice();
        for (org.apache.maven.model.License pomLicense : pomLicenses) {
            LicenseItem resolved = resolve(pomLicense.getName());
            if (resolved == null) {
                resolved = resolveUrl(pomLicense.getUrl());
            }
            if (resolved == null && pomLicense.getName() != null) {
                License license = new License();
                license.setName(pomLicense.getName().trim());
                String url = uri(pomLicense.getUrl());
                if (url != null) {
                    license.setUrl(url);
                }
                resolved = LicenseItem.ofLicense(license);
            }
            if (resolved == null) {
                continue;
            }
            // CycloneDX has either licenses or one expression: as in cyclonedx-maven-plugin, the later of the two kinds stays
            boolean expression = resolved.getExpression() != null;
            if (expression || choice.getItems() != null && choice.getItems().stream().anyMatch(item -> item.getExpression() != null)) {
                choice.setItems(new ArrayList<>());
            }
            choice.addItem(resolved);
        }
        return choice;
    }

    /**
     * The Open Source Initiative moved its license pages from {@code opensource.org/licenses/<id>} to {@code opensource.org/license/<id>},
     * and the SPDX license list knows only the new address, while poms give the old one. For a license that has an
     * "only" and an "or later" form, the list gives the new address to the "or later" form alone; the address names
     * a version and nothing later, so it stands for the "only" form here, as it did in the list before.
     */
    private static LicenseItem resolveUrl(String url) {
        LicenseItem resolved = resolve(url);
        Matcher old = OSI_OLD_URL.matcher(url == null ? "" : url.trim());
        if (resolved != null || !old.matches()) {
            return resolved;
        }
        resolved = resolve("https://opensource.org/license/" + old.group(1));
        if (resolved == null || resolved.getLicense() == null || resolved.getLicense().getId() == null || !resolved.getLicense().getId().endsWith(OR_LATER)) {
            return resolved;
        }
        String id = resolved.getLicense().getId();
        LicenseItem only = resolve(id.substring(0, id.length() - OR_LATER.length()) + "-only");
        return only != null ? only : resolved;
    }

    /**
     * @return the license that the name or URL stands for, else the license expression, else null
     */
    private static LicenseItem resolve(String nameOrUrl) {
        LicenseChoice resolved = nameOrUrl == null ? null : LicenseResolver.resolve(nameOrUrl, false);
        if (resolved == null || resolved.getItems() == null) {
            return null;
        }
        return resolved.getItems().stream().filter(item -> item.getLicense() != null).findFirst()
                .or(() -> resolved.getItems().stream().filter(item -> item.getExpression() != null).findFirst()).orElse(null);
    }

    /**
     * One reference of each type: the first that the pom gives.
     */
    private static void addReference(Component component, ExternalReference.Type type, String url) {
        String uri = uri(url);
        if (uri == null || component.getExternalReferences() != null && component.getExternalReferences().stream().anyMatch(reference -> reference.getType() == type)) {
            return;
        }
        ExternalReference reference = new ExternalReference();
        reference.setType(type);
        reference.setUrl(uri);
        component.addExternalReference(reference);
    }

    private static String uri(String url) {
        if (isBlank(url)) {
            return null;
        }
        try {
            return new URI(url.trim()).toString();
        } catch (URISyntaxException e) {
            return null;
        }
    }

    private static Component.Type componentType(String type) {
        for (Component.Type candidate : Component.Type.values()) {
            if (candidate.getTypeName().equalsIgnoreCase(type)) {
                return candidate;
            }
        }
        throw new SbomException("projectType '" + type + "' is not a CycloneDX component type");
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
