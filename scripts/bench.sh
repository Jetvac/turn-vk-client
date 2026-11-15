#!/usr/bin/env bash
# Repeatable speed, latency and recovery benchmark of TurnVK against a test
# server. Every scenario runs the CLI client for real through VK TURN.
#
#   BENCH_LINK=wdtt://…      the link (required)
#   BENCH_SSH=root@host      the server, for scenarios that change it (optional)
#   BENCH_UNIT=tvkdev        its systemd unit (restart scenario)
#   BENCH_PORT=56010         its UDP port (loss scenario)
#   BENCH_PING=10.66.67.1    the server's address in the tunnel
#   BENCH_BIN=./turnvk       the client
#   BENCH_URL=…              what to download (50 MB); default: the test
#                            endpoint on the server, in the tunnel
#   BENCH_UPURL=…            where to upload (HTTP POST); same default
#
# The endpoint is scripts/bench-endpoint (Go), run on the server (it listens
# on the tunnel address only). Public speed tests (Cloudflare) throttle
# repeated runs and add the internet's noise; set BENCH_URL to use one.
#
#   scripts/bench.sh [scenario…]   default: idle load16 load32 up16 loss16 restart
#   (also: short — a 5 MB download, mostly the first seconds)
#
# Prints one line per scenario and appends it to bench-results.txt (the
# full client logs go to bench-results-logs/). VK
# credentials are saved between runs, so repeated runs within an hour make
# no VK requests (and do not trip VK's per-guest flood limit).
set -u
: "${BENCH_LINK:?set BENCH_LINK}"
BIN=${BENCH_BIN:-./turnvk}
PING=${BENCH_PING:-10.66.67.1}
URL=${BENCH_URL:-http://$PING:8081/?bytes=50000000}
UPURL=${BENCH_UPURL:-http://$PING:8081/}
UNIT=${BENCH_UNIT:-tvkdev}
PORT=${BENCH_PORT:-56010}
OUT=${BENCH_OUT:-bench-results.txt}
LOG=$(mktemp)
trap 'rm -f "$LOG"; cleanup_loss' EXIT

remote() { [ -n "${BENCH_SSH:-}" ] && ssh -o BatchMode=yes "$BENCH_SSH" "$@"; }

# summary pulls the numbers out of one client run.
summary() {
	awk -v name="$1" '
	/_FAIL/ { fail = fail " " $0 }
	/^DOWNLOAD/ { for (i = 1; i <= NF; i++) if ($i == "=") mbit = $(i+1) }
	/^UPLOAD/ { for (i = 1; i <= NF; i++) if ($i == "=") up = $(i+1) }
	/^PING/ {
		for (i = 1; i <= NF; i++) {
			split($i, kv, "=")
			if (kv[1] == "p50") p50 = kv[2]
			if (kv[1] == "p95") p95 = kv[2]
			if (kv[1] == "max") pmax = kv[2]
			if ($i == "lost") plost = $(i+1)
		}
	}
	/^STATS/ && !/down=0.0 / { for (i = 1; i <= NF; i++) if ($i ~ /^loss=/) { v = substr($i, 6); sub(/%/, "", v); ls += v; ln++ } }
	/^HOLD/ { for (i = 1; i <= NF; i++) { split($i, kv, "="); if (kv[1] == "ok") ok = kv[2]; if (kv[1] == "fail") bad = kv[2]; if (kv[1] == "worst") worst = kv[2] } }
	END {
		line = sprintf("%-9s", name)
		if (mbit != "") line = line sprintf(" speed=%s Mbit/s", mbit)
		if (up != "") line = line sprintf(" upload=%s Mbit/s", up)
		if (p95 != "") line = line sprintf(" ping p50=%s p95=%s max=%s ms lost=%s", p50, p95, pmax, plost)
		if (ln > 0) line = line sprintf(" route-loss=%.1f%%", ls / ln)
		if (ok != "") line = line sprintf(" requests ok=%s fail=%s worst=%s", ok, bad, worst)
		if (fail != "") line = line " FAILED:" fail
		print line
	}' "$LOG"
}

run() { # name, client flags…
	local name=$1
	shift
	timeout 400 "$BIN" -link "$BENCH_LINK" "$@" >"$LOG" 2>&1
	local line
	local repo
	repo=$(dirname "$0")
	line="$(date '+%F %T') $(git -C "$repo" rev-parse --short HEAD 2>/dev/null)$(git -C "$repo" diff --quiet 2>/dev/null || echo +) $(summary "$name")"
	echo "$line"
	echo "$line" >>"$OUT"
	# The whole client log, to look into a bad run later.
	mkdir -p "${OUT%.txt}-logs"
	cp "$LOG" "${OUT%.txt}-logs/$(date '+%m%d-%H%M%S')-$name.log"
}

loss_rule() { echo "OUTPUT -p udp --sport $PORT -m statistic --mode random --probability 0.02 -j DROP"; }
cleanup_loss() { remote "iptables -D $(loss_rule) 2>/dev/null" || true; }

for s in "${@:-idle load16 load32 up16 loss16 restart}"; do
	for sc in $s; do
		case $sc in
		idle) run idle -sessions 16 -test -ping "$PING" -pings 50 ;;
		load16) run load16 -sessions 16 -stats -download "$URL" -ping "$PING" -pings 100 ;;
		load32) run load32 -sessions 32 -stats -download "$URL" -ping "$PING" -pings 80 ;;
		short) run short -sessions 16 -download "${URL%=*}=5000000" -ping "$PING" -pings 15 ;;
		up16) run up16 -sessions 16 -stats -upload 20 -upload-url "$UPURL" -ping "$PING" -pings 100 ;;
		loss16)
			# 2% of the server's packets to VK dropped at random.
			if [ -z "${BENCH_SSH:-}" ]; then echo "loss16: needs BENCH_SSH"; continue; fi
			remote "iptables -I $(loss_rule)"
			run loss16 -sessions 16 -stats -download "$URL" -ping "$PING" -pings 100
			cleanup_loss
			;;
		restart)
			if [ -z "${BENCH_SSH:-}" ]; then echo "restart: needs BENCH_SSH"; continue; fi
			(sleep 22 && remote "systemctl restart $UNIT") &
			run restart -sessions 16 -test -hold 45s
			wait
			;;
		*) echo "unknown scenario $sc" ;;
		esac
	done
done
