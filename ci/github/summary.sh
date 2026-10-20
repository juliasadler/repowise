#!/usr/bin/env bash
# Combines the gates' results for the composite action in action.yml: a verdict
# table in the job summary, the verdict step output and, with comment on, one
# pull-request comment that later runs update in place. It never fails the job:
# the gates decide that, and a summary that cannot be written leaves a warning.
# Inputs arrive as environment variables set by action.yml.

set -u

marker="<!-- repowise-ci-summary -->"
work=$(mktemp -d)
trap 'rm -rf "$work" "$SUMMARY_DIR"' EXIT

# EXIT_CODES lists every gate as name=code; a gate that did not run has no code.
gates=()
for pair in $EXIT_CODES; do
  [[ -n "${pair#*=}" ]] && gates+=(--gate "$pair")
done
((${#gates[@]})) || exit 0
args=("$SUMMARY_DIR" "${gates[@]}")

pr=""
comment_id=""
if [[ "$COMMENT" == "true" ]]; then
  pr=$(python -c 'import json, os
event = json.load(open(os.environ["GITHUB_EVENT_PATH"], encoding="utf-8"))
print((event.get("pull_request") or {}).get("number") or "")' 2>/dev/null)
  if [[ -z "$pr" ]]; then
    echo "::notice::This event has no pull request, so no summary comment is posted."
  elif ! command -v gh >/dev/null; then
    echo "::warning::The GitHub CLI (gh) is not installed, so no summary comment is posted."
    pr=""
  else
    comment_id=$(gh api --paginate "repos/$GITHUB_REPOSITORY/issues/$pr/comments" \
      --jq ".[] | select(.body | startswith(\"$marker\")) | .id" 2>/dev/null | head -n 1)
    if [[ -n "$comment_id" ]] && gh api "repos/$GITHUB_REPOSITORY/issues/comments/$comment_id" \
      --jq .body >"$work/previous.md" 2>/dev/null; then
      args+=(--previous "$work/previous.md")
    fi
    args+=(--comment-file "$work/comment.md")
  fi
fi

if ! verdict=$(repowise ci-summary "${args[@]}"); then
  echo "::warning::Could not combine the gate results; each gate's own output still stands."
  exit 0
fi
echo "verdict=$verdict" >>"$GITHUB_OUTPUT"

if [[ -n "$pr" && -s "$work/comment.md" ]]; then
  if [[ -n "$comment_id" ]]; then
    endpoint=(--method PATCH "repos/$GITHUB_REPOSITORY/issues/comments/$comment_id")
  else
    endpoint=(--method POST "repos/$GITHUB_REPOSITORY/issues/$pr/comments")
  fi
  # A pull request from a fork gets a read-only token; the gates still decide.
  gh api "${endpoint[@]}" -F "body=@$work/comment.md" >/dev/null ||
    echo "::warning::Could not post the summary comment. It needs the pull-requests write permission, which a fork's token lacks."
fi
exit 0
