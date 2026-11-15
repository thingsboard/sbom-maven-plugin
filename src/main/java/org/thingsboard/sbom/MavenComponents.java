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
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Makes CycloneDX components of Maven artifacts: the coordinates and hashes of the artifact, and what its effective pom
 * says about it. A component has the fields that {@code cyclonedx-maven-plugin} gives it, by the same rules, except that
 * the old address of a license page of the Open Source Initiative is known too.
 */
final class MavenComponents {
    static final Version SPEC_VERSION = Version.VERSION_16;

    private static final Pattern OSI_OLD_URL = Pattern.compile("https?://(?:www\\.)?opensource\\.org/licenses/([^/]+?)(?:\\.php|\\.html|/)?", Pattern.CASE_INSENSITIVE);

    private final MavenSession session;
    private final ProjectBuilder projectBuilder;
    private final ArtifactHandlerManager artifactHandlerManager;
    private final MavenProject project;

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
            describe(effectiveProject(group, name, version), component);
        } catch (ProjectBuildingException e) {
            throw new SbomException("The pom of " + component.getPurl() + " could not be read, so the SBOM cannot give its license: " + e.getMessage(), e);
        }
        return component;
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
            if (resolve(choice, pomLicense.getName()) || resolveUrl(choice, pomLicense.getUrl()) || pomLicense.getName() == null) {
                continue;
            }
            License license = new License();
            license.setName(pomLicense.getName().trim());
            String url = uri(pomLicense.getUrl());
            if (url != null) {
                license.setUrl(url);
            }
            choice.addLicense(license);
        }
        return choice;
    }

    /**
     * The Open Source Initiative moved its license pages from {@code opensource.org/licenses/<id>} to {@code opensource.org/license/<id>},
     * and the SPDX license list knows only the new address, while poms give the old one.
     */
    private static boolean resolveUrl(LicenseChoice choice, String url) {
        if (resolve(choice, url)) {
            return true;
        }
        Matcher old = OSI_OLD_URL.matcher(url == null ? "" : url.trim());
        return old.matches() && resolve(choice, "https://opensource.org/license/" + old.group(1));
    }

    private static boolean resolve(LicenseChoice choice, String nameOrUrl) {
        LicenseChoice resolved = nameOrUrl == null ? null : LicenseResolver.resolve(nameOrUrl, false);
        if (resolved == null || resolved.getItems() == null) {
            return false;
        }
        for (LicenseItem item : resolved.getItems()) {
            if (item.getLicense() != null) {
                choice.addLicense(item.getLicense());
                return true;
            }
        }
        for (LicenseItem item : resolved.getItems()) {
            if (item.getExpression() != null) {
                // CycloneDX has either licenses or one expression, so the expression stands alone
                choice.setItems(new ArrayList<>(List.of(item)));
                return true;
            }
        }
        return false;
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
