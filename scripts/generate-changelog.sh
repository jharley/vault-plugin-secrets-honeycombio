#!/bin/sh
#
# Generate a changelog section for a release from merged PRs.
# Groups PRs by label in Keep a Changelog format.
#
# Usage:
#   ./scripts/generate-changelog.sh v0.2.0 [v0.1.0]
#
# Arguments:
#   $1 - Version tag being released (required)
#   $2 - Previous version tag (optional, auto-detected if omitted)
#
# Requires: gh CLI (authenticated), jq

set -e

VERSION="${1:?Usage: $0 <version> [previous-version]}"
PREVIOUS="${2:-}"
REPO="$(gh repo view --json nameWithOwner -q .nameWithOwner)"

# Auto-detect previous tag if not provided.
if [ -z "${PREVIOUS}" ]; then
  PREVIOUS="$(git tag --sort=-version:refname | grep -v "^${VERSION}$" | head -1)"
fi

# Build the search query for merged PRs.
if [ -n "${PREVIOUS}" ]; then
  TAG_SHA="$(gh api "repos/${REPO}/git/ref/tags/${PREVIOUS}" -q '.object.sha')"
  TAG_TYPE="$(gh api "repos/${REPO}/git/ref/tags/${PREVIOUS}" -q '.object.type')"
  if [ "${TAG_TYPE}" = "tag" ]; then
    COMMIT_SHA="$(gh api "repos/${REPO}/git/tags/${TAG_SHA}" -q '.object.sha')"
  else
    COMMIT_SHA="${TAG_SHA}"
  fi
  SINCE_DATE="$(gh api "repos/${REPO}/git/commits/${COMMIT_SHA}" -q '.committer.date')"
  QUERY="repo:${REPO} is:pr is:merged merged:>${SINCE_DATE}"
else
  QUERY="repo:${REPO} is:pr is:merged"
fi

TMPFILE="$(mktemp)"
trap 'rm -f "${TMPFILE}"' EXIT

# Fetch merged PRs as JSON.
# Fetch only the fields we need (avoids jq choking on control chars in PR bodies).
gh api -X GET 'search/issues' \
  -f q="${QUERY}" \
  -f sort=created \
  -f order=asc \
  -f per_page=100 \
  -q '[.items[] | {title, number, labels: [.labels[].name]}]' > "${TMPFILE}"

DATE="$(date +%Y-%m-%d)"
DISPLAY_VERSION="$(echo "${VERSION}" | sed 's/^v//')"

# Filter out no-changelog PRs and strip conventional commit prefixes from titles.
FILTERED="$(jq '
  [.[]
   | select(.labels | index("no-changelog") | not)
   | .title |= sub("^[a-z]+!?: "; "")
  ]' "${TMPFILE}")"

# Print a section for a given label.
print_section() {
  title="$1"
  label="$2"
  items="$(echo "${FILTERED}" | jq -r --arg label "${label}" \
    '.[] | select(.labels | index($label)) | "- \(.title) (#\(.number))"')"
  if [ -n "${items}" ]; then
    printf '\n### %s\n\n%s\n' "${title}" "${items}"
  fi
}

# Print PRs that don't match any known label.
print_other() {
  items="$(echo "${FILTERED}" | jq -r '
    .[] |
    select(
      (.labels | index("breaking-change") | not) and
      (.labels | index("feature") | not) and
      (.labels | index("bug") | not) and
      (.labels | index("improvement") | not) and
      (.labels | index("dependencies") | not)
    ) | "- \(.title) (#\(.number))"')"
  if [ -n "${items}" ]; then
    printf '\n### Other Changes\n\n%s\n' "${items}"
  fi
}

echo "## ${DISPLAY_VERSION} (${DATE})"
print_section "Breaking Changes" "breaking-change"
print_section "Features" "feature"
print_section "Bug Fixes" "bug"
print_section "Improvements" "improvement"
print_section "Dependencies" "dependencies"
print_other
