#!/usr/bin/env bash
# Run only as a child of phantom exec. Never enable shell tracing.
set +x
set -euo pipefail
fail() { printf '%s\n' "$1" >&2; exit 1; }
usage() { fail 'Usage: github.sh OWNER/REPO list [PAGE] | update-branch NUMBER HEAD_SHA | auto-merge NUMBER MERGE|SQUASH|REBASE'; }
[[ $# -ge 2 ]] || usage
repo=$1 action=$2
shift 2
[[ $repo =~ ^[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9_.-]+$ && ${repo#*/} != . && ${repo#*/} != .. ]] || usage
command -v jq >/dev/null || fail 'jq is required'
command -v curl >/dev/null || fail 'curl is required'
# Reject remote endpoints, URL query/fragment injection and alternate routes.
base=${GITHUB_TOKEN_BASE_URL-}
[[ $base =~ ^http://127\.0\.0\.1:[0-9]+/github_api(/_phantom/[A-Za-z0-9_-]+/)?$ ]] || fail 'Run under phantom exec with the built-in GITHUB_TOKEN route'
[[ ${PHANTOM_PROXY_TOKEN-} =~ ^[A-Za-z0-9_-]+$ ]] || fail 'Missing Phantom session authentication'
base=${base%/}
request() {
    local method=$1 path=$2 payload=${3-} response status
    # Disable curlrc, redirects, ambient HTTP proxies, tracing and retries.
    # Feed the session-bearing URL/header over stdin, not process arguments.
    if ! response=$({
        printf 'url = "%s/%s"\n' "$base" "$path"
        printf 'header = "x-phantom-proxy-token: %s"\n' "$PHANTOM_PROXY_TOKEN"
    } | curl -q --config - --silent --fail --noproxy '*' \
        --proto '=http' --connect-timeout 10 --max-time 60 \
        --write-out '\n%{http_code}' --request "$method" --header 'Accept: application/vnd.github+json' \
        --header 'X-GitHub-Api-Version: 2022-11-28' \
        --header 'Content-Type: application/json' --data-binary "$payload" 2>/dev/null); then
        fail 'GitHub request failed; inspect permissions, rate limits and proxy health outside agent logs'
    fi
    status=${response##*$'\n'}
    [[ $status =~ ^2[0-9][0-9]$ ]] || fail 'GitHub returned an unexpected HTTP status'
    printf '%s' "${response%$'\n'*}"
}
case $action in
    list)
        [[ $# -le 1 ]] || usage
        page=${1:-1}
        [[ $page =~ ^[1-9][0-9]*$ ]] || usage
        response=$(request GET "repos/$repo/pulls?state=open&per_page=100&page=$page")
        jq -es 'if length == 1 and (.[0] | type == "array") then .[0] | map({number, title, state, head_sha: .head.sha}) else error("Invalid PR list") end' <<<"$response"
        ;;
    update-branch)
        [[ $# -eq 2 && $1 =~ ^[1-9][0-9]*$ && $2 =~ ^[0-9a-fA-F]{40}$ ]] || usage
        payload=$(jq -cn --arg sha "$2" '{expected_head_sha: $sha}')
        request PUT "repos/$repo/pulls/$1/update-branch" "$payload" >/dev/null
        printf '%s\n' 'Branch update accepted; wait for completion and rerun checks before enabling auto-merge.'
        ;;
    auto-merge)
        [[ $# -eq 2 && $1 =~ ^[1-9][0-9]*$ && $2 =~ ^(MERGE|SQUASH|REBASE)$ ]] || usage
        pr=$(request GET "repos/$repo/pulls/$1")
        id=$(jq -ers 'if length == 1 then .[0].node_id | select(type == "string" and length > 0) else error("Invalid PR") end' <<<"$pr")
        payload=$(jq -cn --arg id "$id" --arg method "$2" \
            '{query: "mutation($id:ID!,$method:PullRequestMergeMethod!){enablePullRequestAutoMerge(input:{pullRequestId:$id,mergeMethod:$method}){pullRequest{number}}}", variables:{id:$id,method:$method}}')
        response=$(request POST graphql "$payload")
        jq -es --argjson number "$1" 'length == 1 and (.[0] | ((.errors // []) | length == 0) and (.data.enablePullRequestAutoMerge.pullRequest.number == $number))' <<<"$response" >/dev/null || fail 'GitHub did not confirm auto-merge; check repository policy and permissions'
        printf '%s\n' 'Auto-merge enabled; GitHub controls when the pull request merges.'
        ;;
    *) usage ;;
esac
