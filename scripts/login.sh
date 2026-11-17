#!/usr/bin/env bash
# usage: scripts/login.sh <label>   (PKCE login only; saves Cognito access token to ~/.cache/sn-obo/<label>.at)
set -euo pipefail
LABEL=${1:?usage: scripts/login.sh <label>}
# shellcheck disable=SC1090
source "${SN_OBO_ENV:-$HOME/sn-obo.env}"
CID=${LOGIN_CLIENT_ID:-$GATE1_ID}
REDIR=${REDIRECT_URI:-http://localhost:6274/oauth/callback}

V=$(openssl rand -base64 48 | tr -d '=+/\n' | cut -c1-64)
C=$(printf '%s' "$V" | openssl dgst -sha256 -binary | base64 | tr '+/' '-_' | tr -d '=')
echo; echo "1) Open in a NEW private window and sign in as $LABEL:"
echo "$COG_URL/oauth2/authorize?response_type=code&client_id=$CID&redirect_uri=$REDIR&scope=openid+email+profile+servicenow-api%2Faccess&identity_provider=EntraID&code_challenge=$C&code_challenge_method=S256&prompt=login"
echo; read -rp "2) Paste the code (or the full callback URL): " IN
CODE=$(printf '%s' "$IN" | sed -n 's/.*[?&]code=\([^&# ]*\).*/\1/p')
CODE=${CODE:-$IN}

RESP=$(curl -s -X POST "$COG_URL/oauth2/token" -d grant_type=authorization_code \
  --data-urlencode "client_id=$CID" --data-urlencode "code=$CODE" \
  --data-urlencode "redirect_uri=$REDIR" --data-urlencode "code_verifier=$V")
AT=$(printf '%s' "$RESP" | jq -r '.access_token // empty' 2>/dev/null || true)
if [ -z "$AT" ]; then
  echo "login failed: $(printf '%s' "$RESP" | jq -c '{error,error_description}' 2>/dev/null || echo 'non-JSON response')" >&2
  exit 1
fi

umask 077
D=$HOME/.cache/sn-obo; mkdir -p "$D"; chmod 700 "$D"
printf '%s' "$AT" > "$D/$LABEL.at"; chmod 600 "$D/$LABEL.at"
echo; echo "saved: $D/$LABEL.at"
P=$(printf '%s' "$AT" | cut -d. -f2 | tr '_-' '/+')
while [ $(( ${#P} % 4 )) -ne 0 ]; do P="$P="; done
printf '%s' "$P" | base64 -d | jq -c '{username,client_id,scope,exp}'
