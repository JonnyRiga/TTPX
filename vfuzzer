#!/bin/bash

DEFAULT_WORDLIST="/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt"

show_help() {
    echo "Usage: vfuzzer <DOMAIN> [IP] [http|https] [WORDLIST] <FS> [-t THREADS] [-o OUTFILE] [-p DELAY] [-k] [-r] [--dns]"
    echo "   -h, --help  Display this help and exit"
    echo
    echo "  DOMAIN      Target domain (required)"
    echo "  IP          Target IP to connect to — defaults to DOMAIN (vhost mode only)"
    echo "  http|https  Protocol shorthand — defaults to http"
    echo "  WORDLIST    Path to wordlist (default: subdomains-top1million-110000.txt)"
    echo "  FS          Filter size (optional, always last positional — omit to auto-calibrate)"
    echo "  -t THREADS  Number of threads (default: ffuf default 40)"
    echo "  -o OUTFILE  Save results to file (JSON format)"
    echo "  -p DELAY    Delay between requests in seconds (e.g. 0.1) — useful against rate-limited targets"
    echo "  -k          Skip TLS certificate verification (required for self-signed certs)"
    echo "  -r          Follow redirects"
    echo "  --dns       Subdomain mode: fuzz http://FUZZ.DOMAIN instead of Host header"
    echo
    echo "Examples:"
    echo "  vfuzzer example.com 1234"
    echo "  vfuzzer example.com 10.10.10.5 1234"
    echo "  vfuzzer example.com 10.10.10.5 https 1234 -k -t 20 -o results.json"
    echo "  vfuzzer example.com 10.10.10.5 https -k"
    echo "  vfuzzer example.com --dns 1234"
}

if [[ "$1" == "-h" || "$1" == "--help" ]]; then
    show_help
    exit 0
fi

# Extract flags first, rebuild args without them
THREADS=""
OUTFILE=""
DELAY=""
INSECURE=false
FOLLOW_REDIRECTS=false
DNS_MODE=false
positional=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        -t) THREADS="$2"; shift 2 ;;
        -o) OUTFILE="$2"; shift 2 ;;
        -p) DELAY="$2"; shift 2 ;;
        -k) INSECURE=true; shift ;;
        -r) FOLLOW_REDIRECTS=true; shift ;;
        --dns) DNS_MODE=true; shift ;;
        *)  positional+=("$1"); shift ;;
    esac
done
set -- "${positional[@]}"

if [ "$#" -lt 1 ]; then
    echo "Error: DOMAIN is required."
    show_help
    exit 1
fi

DOMAIN="$1"
WORDLIST="$DEFAULT_WORDLIST"
PROTO="http"
TARGET=""
FS=""

# Check if last arg is a plain integer (FS)
last="${@: -1}"
if [[ "$last" =~ ^[0-9]+$ ]]; then
    FS="$last"
    middle=("${@:2:$#-2}")
else
    middle=("${@:2}")
fi

# Parse optional middle args
for arg in "${middle[@]}"; do
    if [[ "$arg" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        TARGET="$arg"
    elif [[ "$arg" == "https" || "$arg" == "http" ]]; then
        PROTO="$arg"
    else
        WORDLIST="$arg"
    fi
done

TARGET="${TARGET:-$DOMAIN}"
URL="${PROTO}://${TARGET}"

echo "[*] Domain:   $DOMAIN"
echo "[*] Mode:     $($DNS_MODE && echo 'subdomain (--dns)' || echo 'vhost (Host header)')"
$DNS_MODE || echo "[*] Target:   $TARGET"
echo "[*] Wordlist: $WORDLIST"
[[ -n "$FS" ]] && echo "[*] FS:       $FS"
[[ -n "$THREADS" ]] && echo "[*] Threads:  $THREADS"
[[ -n "$DELAY" ]] && echo "[*] Delay:    ${DELAY}s"
$INSECURE && echo "[*] TLS:      insecure (-k)"
$FOLLOW_REDIRECTS && echo "[*] Redirects: follow (-r)"
[[ -n "$OUTFILE" ]] && echo "[*] Output:   $OUTFILE"
echo

if $DNS_MODE; then
    FFUF_CMD=(ffuf -H "User-Agent: PENTEST" -c -w "$WORDLIST" -u "${PROTO}://FUZZ.${DOMAIN}" -mc all)
else
    FFUF_CMD=(ffuf -H "Host: FUZZ.$DOMAIN" -H "User-Agent: PENTEST" -c -w "$WORDLIST" -u "$URL" -mc all)
fi
if [[ -n "$FS" ]]; then
    FFUF_CMD+=(-fs "$FS")
else
    FFUF_CMD+=(-ac)
fi
[[ -n "$THREADS" ]] && FFUF_CMD+=(-t "$THREADS")
[[ -n "$DELAY" ]] && FFUF_CMD+=(-p "$DELAY")
$INSECURE && FFUF_CMD+=(-k)
$FOLLOW_REDIRECTS && FFUF_CMD+=(-r)
[[ -n "$OUTFILE" ]] && FFUF_CMD+=(-o "$OUTFILE" -of json)

"${FFUF_CMD[@]}"
