#!/usr/bin/env bash
#
# SPDX-FileCopyrightText: Copyright ThingsBoard, Inc.
# SPDX-License-Identifier: Apache-2.0
#

# Releases the plugin: see "Releasing" in README.md.
# Usage: ./release.sh <release version> [<next development version>]
# Example: ./release.sh 1.0.0 1.0.1-SNAPSHOT

set -euo pipefail

readonly DEPLOY_SERVER_ID=thingsboard-repo-deploy

step() { printf '\n==> %s\n' "$*"; }
die() { printf '\nERROR: %s\n' "$*" >&2; exit 1; }

[ $# -ge 1 ] && [ $# -le 2 ] || die "usage: $0 <release version> [<next development version>]"
readonly version=$1 next_version=${2:-}
readonly tag=v$version branch=release/$version

[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "release version must look like 1.2.3, got '$version'"
[ -z "$next_version" ] || [[ $next_version =~ ^[0-9]+\.[0-9]+\.[0-9]+-SNAPSHOT$ ]] \
    || die "next development version must look like 1.2.4-SNAPSHOT, got '$next_version'"

cd "$(dirname "$0")"

step "Checking the environment"
command -v gh >/dev/null || die "the GitHub CLI (gh) is required"
gh auth status >/dev/null 2>&1 || die "gh is not logged in: run 'gh auth login'"
settings=${MAVEN_SETTINGS:-$HOME/.m2/settings.xml}
grep -q "<id>$DEPLOY_SERVER_ID</id>" "$settings" 2>/dev/null \
    || die "$settings has no <server> with id $DEPLOY_SERVER_ID: release:perform could not deploy"
[ "$(git branch --show-current)" = main ] || die "run this from the main branch"
[ -z "$(git status --porcelain)" ] || die "the working tree has changes"
git fetch --quiet origin main
[ "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)" ] || die "main is not up to date with origin/main"
! git rev-parse --quiet --verify "refs/tags/$tag" >/dev/null || die "tag $tag already exists locally"
[ -z "$(git ls-remote --tags origin "refs/tags/$tag")" ] || die "tag $tag already exists on GitHub"
[ -z "$(git ls-remote --heads origin "refs/heads/$branch")" ] || die "branch $branch already exists on GitHub"

step "Preparing $tag on $branch"
git switch --create "$branch"
./mvnw -B release:clean
./mvnw -B release:prepare -Dresume=false -DreleaseVersion="$version" ${next_version:+-DdevelopmentVersion="$next_version"}
git log --oneline -2

step "Opening the release PR"
git push --set-upstream origin "$branch"
pr_url=$(gh pr create --base main --head "$branch" --title "chore: release $tag" \
    --body "Release commit tagged $tag, followed by the commit that starts the next development version. Created by release.sh.")
echo "$pr_url"

step "Waiting for the PR checks"
# The checks take a few seconds to show up after the PR is opened
for _ in $(seq 30); do
    gh pr checks "$pr_url" >/dev/null 2>&1 && break
    [ $? -eq 8 ] && break # 8: checks pending
    sleep 5
done
gh pr checks "$pr_url" --watch --fail-fast || die "the PR checks failed: see $pr_url"

step "Waiting for the PR to be merged: merge $pr_url (merge commit) to continue"
while :; do
    state=$(gh pr view "$pr_url" --json state --jq .state)
    [ "$state" = MERGED ] && break
    [ "$state" = CLOSED ] && die "the PR was closed without merging"
    sleep 10
done

step "Pushing $tag"
git fetch --quiet origin main
git merge-base --is-ancestor "$tag" origin/main || die "$tag is not in main's history: was the PR squashed or rebased?"
git push origin "refs/tags/$tag"

step "Building $tag and deploying it to $DEPLOY_SERVER_ID"
./mvnw -B release:perform

step "Creating the GitHub Release"
gh release create "$tag" --verify-tag --generate-notes --title "$tag" \
    "target/checkout/target/sbom-maven-plugin-$version.jar"

step "Cleaning up"
./mvnw -B -q release:clean
git switch main
git pull --ff-only --quiet
git branch --delete "$branch"

step "Released $tag"
