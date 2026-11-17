#!/usr/bin/env bash
# usage: scripts/call.sh <label> <tool> ['{"json":"args"}']
#   uses the token saved by scripts/login.sh <label> (or M2M token in ~/.cache/sn-obo/<label>.at)
set -euo pipefail
LABEL=${1:?usage: scripts/call.sh <label> <tool> [json-args]}
TOOL=${2:?tool name required}
ARGS=${3:-'{}'}
B=${BASE_URL:-http://localhost:8000}
AT=$(cat "$HOME/.cache/sn-obo/$LABEL.at")
BODY=$(jq -cn --arg t "$TOOL" --argjson a "$ARGS" '{jsonrpc:"2.0",id:1,method:"tools/call",params:{name:$t,arguments:$a}}')
RESP=$(curl -s -w '\n%{http_code}' -X POST "$B/mcp" -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' -H "Authorization: Bearer $AT" -d "$BODY")
CODE=$(tail -n1 <<<"$RESP")
[ "$CODE" = 200 ] || { echo "HTTP $CODE"; sed '$d' <<<"$RESP"; exit 1; }
sed '$d' <<<"$RESP" | sed -n 's/^data: //p' | jq '.result | if .isError then {error: .content[0].text} else .structuredContent end'
