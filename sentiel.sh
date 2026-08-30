#!/bin/bash
###############################################################################
#  sentinel.sh — Cryptocurrency-Miner & Rogue-Process Watchdog
#  ----------------------------------------------------------------------------
#  A single-file, self-contained, persistent background watchdog that actively
#  hunts and terminates:
#    1. Known cryptocurrency-mining processes (name / path / command-line list)
#    2. Resource-hogging rogue processes using >70% CPU sustained over 5s
#    3. KVM/QEMU virtual machines (to block hardware-assisted mining rigs)
#    4. Mining processes inside LXC containers and Docker containers
#  and, if not already running under systemd, installs and starts itself as a
#  hardened `sentinel.service` unit so it survives reboots.
#
#  Author design note:
#  ----------------------------------------------------------------------------
#        "made by IamGunpoint"
#
#  REQUIREMENTS
#  ------------
#    * Must run as root (every operation requires privileged access).
#    * Standard Linux binaries only: bash, ps, pgrep, pidof, awk, grep, sed,
#      tr, cut, systemctl, kill, nsenter, docker / lxc (optional, best-effort).
#
#  LEGAL / SAFETY WARNING
#  ----------------------
#    This tool is defensive & intended for admins on machines they own.
#    Killing KVM/QEMU and stopping high-CPU processes is DESTRUCTIVE to any
#    legitimate workload (CI runners, build VMs, heavy render farms). Review
#    the SAFE / ALLOWLIST variables below and tune before production use.
###############################################################################

# ────────────────────────────────────────────────────────────────────────────
# SECTION 0 : CONFIGURATION & TUNABLES
# ────────────────────────────────────────────────────────────────────────────
SENTINEL_VERSION="1.2.0"
SENTINEL_NAME="sentinel"

# Logging targets
LOG_FILE="/var/log/sentinel.log"

# Resource thresholds
CPU_PERCENT_THRESHOLD=70          # a process exceeding this %CPU ...
CPU_SUSTAIN_SECONDS=5             # ... held for >= this many seconds is a threat

# Polling interval (sub-second => near-instant reaction)
POLL_INTERVAL=0.5

# How many CPU samples to buffer to detect a *sustained* breach.
# ceil(CPU_SUSTAIN_SECONDS / POLL_INTERVAL) + 2
SAMPLES=$(awk "BEGIN{printf \"%d\", ($CPU_SUSTAIN_SECONDS/$POLL_INTERVAL)+2}")

# Re-discover/refresh the container runtimes every N loops (cheap + robust)
CONTAINER_REFRESH_EVERY=10

# Aggressive heuristic: kill ANY unknown binary running from a world-writable
# drop zone (/tmp, /dev/shm, /var/tmp). Set to 0 if you run temp binaries
# legitimately and only want signature-based detection.
KILL_SUSPICIOUS_PATH=1

# Memory monitor (NEW). If a single process holds >MEM_PERCENT_THRESHOLD % of
# total RAM for >= MEM_SUSTAIN_SECONDS it is terminated. Set KILL_MEM_HOGS=0 to
# disable (the host CPU monitor still runs). MEM_SAMPLES mirrors the CPU logic.
KILL_MEM_HOGS=1
MEM_PERCENT_THRESHOLD=50
MEM_SUSTAIN_SECONDS=5
MEM_SAMPLES=$(awk "BEGIN{printf \"%d\", ($MEM_SUSTAIN_SECONDS/$POLL_INTERVAL)+2}")

# Kernel clock ticks per second (100 on almost all Linux). Used to convert the
# /proc/<pid>/stat cumulative CPU-time delta into a fraction of one core.
HZ=$(getconf CLK_TCK 2>/dev/null); HZ=${HZ:-100}

# ────────────────────────────────────────────────────────────────────────────
# SECTION 0a : APPROVED / SAFETY LISTS  (EDIT THESE!)
# ────────────────────────────────────────────────────────────────────────────
# Processes that are ALWAYS immune from the >70% CPU monitor. Name must equal
# the process `comm` basename (lowercase, ≤15 chars on Linux).
declare -a SAFE_CPUS=(
    systemd kernel_init kthreadd
    kworker* khubd kswapd ksoftirqd kdmflush  # kernel threads (never touch)
    Xorg Xwayland gnome-shell plasmashell      # display/desktop compositors
    chrome chromium firefox                    # browsers legitimately spike
    mysqld mariadbd postgres java node nodejs  # database/appservers
    python python3 php apache2 nginx httpd     # web/scripting runtimes
    make gcc cc clang llvm dcc                 # compilers/CI
    top htop ps pgrep pidof watch dd ddrescue  # the monitor's own kin
    bash dash sh zsh                          # safety: never kill shells of root
    sentinel sentineld                         # never kill ourselves
    # Login terminals & essential system services: STILL these are legitimate and
    # MUST never be killed by the miner matcher.
    agetty login mingetty getty init systemd-logind dbus-daemon rsyslogd sshd crond
    atd NetworkManager systemd-udevd polkitd chronyd auditd edac-poller
)

# Explicitly allow KVM/QEMU VMs that carry one of these strings in their
# command line (e.g. "windows-lab" or a known production guest). Empty = block ALL.
declare -a QEMU_ALLOW_SUBSTRINGS=( "trusted-guest" "seedbox" )

# ────────────────────────────────────────────────────────────────────────────
# SECTION 1 : MINER LIST
# ────────────────────────────────────────────────────────────────────────────
# 1a. Known miner *process names* (comm / executable basename, case-folded).
#     This is a curated census of the most commonly deployed coin-miners.
#     The monitor matches these BOTH as an exact process name and as a regex
#     substring inside the full command line, so renamed binaries still trip.
declare -a MINER_NAMES=(
    # ---- Monero / CryptoNight / RandomX (XMRig family & forks) ----
    xmrig xmrig2 xmrig-nightly xmrig64 xmrig32 xmrigd xmrig-miner
    xmrig.exe kawpowminer xmr-stak xmr-stak-cpu xmr-stak-amd xmr-stak-nvidia
    xmrminer xmrigCC xmrigcc xmrig-mo xmrig-proxy xmrig-benchmark
    moneroocean xmrig-mo cpuminer xmrig-soft
    # ---- Ethash / Ethereum & its forks ----
    ethminer ethminer64 ethminer-2 ethminer-3 ethminer1 claymore
    claymore-ethminer claymore-dual Claymore_XMR PhoenixMiner phoenixminer
    phoenixminer_linux phoenixminer.exe ethosl --ethminer ethminer72 nvidia-miner
    ethash miner minereth ethereum classic
    # ---- General CUDA/OpenCL miners ----
    ccminer ccminer-cryptonight ccminer-bbs ccminer-tpruvot ccminer-x11
    cgminer cgminer.exe sgminer sgminer-x11 sgminer-5 sgminer-4
    bfgminer minerd pooler-cpuminer cpuminer cpuminer-opt cpuminer-gr
    nicehash nheqminer nheqminer.exe nhworker nh-gpu nicehash-benchmark
    claymore-dual claymore-eth xmrig-nvidia ethosdevice ethdcminer
    # ---- Web / JavaScript / in-browser & scripted miners ----
    coinhive cryptonight-hashing jsminer webminer
    # ---- Gaming / social miners & disguised names ----
    cryptonight minerx nnminer python2 python3-plugminer
    # ---- Recent / pool-specific & renamed variants ----
    t-rex t-rex.exe t-rex-gpu TRex nanominer nanominer-src nanominer.exe
    nanominer-web davinci miner-cryptonight awesome-miner awesome
    lolminer lolminer.exe lolMiner teamredminer teamredminer.exe
    nbminer nbminer.exe honey-miner honey_miner honeygainer
    gminer gminer.exe rigel rigelminer kryptex miniz miniz.exe dush
    wildrig wildrig-multi wildrig.exe hushminer photonminer srbm
    xmrig-nga xmrig-old xmrig-legacy xmrig-clone miner-rogue cryptonighthash
    zcash-miner zm minerz ninja-miner java-miner
    # ---- Cryptocurrency daemons often bundled with miners ----
    cryptonightproxy proxyminer miningproxy eth-proxy stratum proxy
    # ---- HiveOS / mining OS helpers that run the daemon ----
    minerstat rig-rig worker manager hw-monitor
    # ---- Generic / look-alike & anti-forensic renames ----
    syslogd cron-helper system-update network-helpers logrotate
    cloud-sync backup-sync update-helper service-mon mtnmp
    miner8 minergate minergate-cli minergate-v2
    # ---- Common drop-in trojans that fetch & run a miner ----
    kdevtmpfsi kinsing solr xmrig-related chronocrypts sh-ui
)

# 1b. Command-line / string signatures (substrings, case-insensitive) that mark
#     a process as a miner regardless of its binary name. These catch renamed
#     copies and shell wrappers. Applied to the full `ps args` line.
declare -a MINER_STRINGS=(
    # Miner-pool / protocol endpoints (strong signals, not generic args)
    "stratum+tcp" "stratum+ssl" "stratum+tls" "stratum2" "stratum://" "stratum+tcp://"
    "nicehash" "nanopool" "minergate" "minexmr" "supportxmr" "moneroocean"
    "dwarfpool" "hashspeed" "kryptex" "ethermine" "ethpool" "f2pool"
    "prohashing" "miningpoolhub" "mining-pool" "pool.mine" "minexmr.com"
    # Explicit coin-miner CLI flags (the ones that are actually miner-specific)
    "--coin=monero" "--algo=randomx" "--algo=cryptonight" "--donate-level"
    "--nicehash" "--opencl" "--cuda" "--cpu-affinity" "--cpu-priority"
    "--randomx" "--api-bind" "--bminer"
    # Well-known miner binary footprints (also caught by name list, but useful)
    "xmrig" "xmr-stak" "ethminer" "minerd" "cgminer" "cpuminer" "nheqminer"
    "claymore" "phoenixminer" "nanominer" "lolminer" "teamredminer" "gminer"
    "minergate-cli" "kdevtmpfsi" "kinsing"
    # Mining algorithms appearing in a hostile cmd line
    "cryptonight" "cn_slow_hash" "equihash" "lyra2" "x16r" "x16s" "sha256d"
    "keccak" "blake2b" "decred" "--farm-reward" "eth-proxy" "miningproxy"
    # Drop-in downloader/wrapper patterns
    "wget.*\\.sh" "curl.*\\.sh" "/tmp/.*miner"
)
# 1c. Suspicious executable LOCATIONS — coin miners almost universally drop into
#     world-writable/anon dirs and reuse cutesy names. If a flagged name or an
#     unknown binary is exec'd straight from here, treat it as a miner.
declare -a SUSPICIOUS_PATHS=(
    "/tmp" "/var/tmp" "/dev/shm" "/dev/shm/*" "/run/user/*/tmp" "/var/run/tmp"
    "/tmp/*" "/dev/shm/.*" "/var/tmp/.*" "/usr/local/bin/*.sock" "/proc/*/fd"
)

# Build a case-insensitive extended-regex alternation once at startup.
# Bash's `[[ =~ ]]` is case-SENSITIVE, so lowercase both the patterns and the
# scanned input for case-insensitive matching.
_compile_patterns() {
    local names_str strings_str
    names_str=$(printf '|%s' "${MINER_NAMES[@]}");  names_str="${names_str:1}"
    strings_str=$(printf '|%s' "${MINER_STRINGS[@]}"); strings_str="${strings_str:1}"
    MINER_NAME_RE="(^|[^a-zA-Z0-9_.-])("$(tr 'A-Z' 'a-z' <<<"$names_str")")([^a-zA-Z0-9_.-]|\$)"
    MINER_STRING_RE="("$(tr 'A-Z' 'a-z' <<<"$strings_str")")"
    # Export so the container `nsenter`/`lxc` child shells can use them.
    export MINER_NAME_RE MINER_STRING_RE
}
_compile_patterns

# True if the executable backing a pid lives in a world-writable/anon location
# (the classic drop zone for coin-miner binaries).
is_suspicious_path() {
    local pid="$1"
    local exe
    exe=$(readlink -f "/proc/${pid}/exe" 2>/dev/null) || return 1
    [[ -z "$exe" ]] && return 1
    case "$exe" in
        /tmp/*|/var/tmp/*|/dev/shm/*|/var/run/*|/run/user/*/tmp/*)
            return 0 ;;
        *)  return 1 ;;
    esac
}


# Cumulative CPU time (utime+stime) for a pid, in clock ticks. Field positions
# after the "(comm)" block: state,ppid,pgrp,session,tty,tpgid,flags,minflt,
# cminflt,majflt,cmajflt,utime,stime -> utime is a[12], stime is a[13].
read_cpu_ticks() {
    local pid=$1
    awk '{ i = index($0, ")"); r = substr($0, i + 2); n = split(r, a, " ");
           if (n >= 13) print a[12] + a[13] }' "/proc/${pid}/stat" 2>/dev/null
}

# Resident set size of a pid in kB.
read_rss_kb() {
    awk '/VmRSS:/ { print $2 }' "/proc/${1}/status" 2>/dev/null
}

# True if a process's executable lives in a standard, package-managed location.
# Non-standard locations (tmp, shm, home, /run, cwd) mark it as untrusted.
is_trusted_exe() {
    local pid=$1 exe
    exe=$(readlink -f "/proc/${pid}/exe" 2>/dev/null)
    [[ -z "$exe" ]] && return 1
    case "$exe" in
        /usr/bin/*|/usr/sbin/*|/bin/*|/sbin/*|\
        /usr/libexec/*|/usr/lib/*|/usr/lib64/*|/lib/*|/lib64/*) return 0 ;;
        *) return 1 ;;
    esac
}

# Decide whether a HIGH-RESOURCE process may be terminated even if it matched
# the immune list (e.g. is named python/java/mysql). We override the immunity
# when the process is running from an untrusted location or via a suspicious
# path in its command line — this catches miners that masquerade as a normal
# service but were dropped into /tmp, /dev/shm, or a user's home directory.
would_terminate_hog() {
    local pid=$1 name=$2 cmdline
    is_immune "$name" "$pid" || return 0            # not immune -> kill
    is_trusted_exe "$pid" || return 0               # immune but untrusted exe -> kill
    cmdline=$(tr '\0' ' ' < "/proc/${pid}/cmdline" 2>/dev/null)
    [[ "$cmdline" =~ /tmp/|/dev/shm|/var/tmp|/run/user/ ]] && return 0
    return 1                                         # genuinely trusted -> protect
}

# ────────────────────────────────────────────────────────────────────────────
# SECTION 2 : GLOBAL STATE & HELPERS
# ────────────────────────────────────────────────────────────────────────────
LOCK="/var/lock/${SENTINEL_NAME}.lock"
declare -A CPU_HITS            # pid -> count of consecutive breaches
declare -A CPU_PIDMAP          # pid -> name snapshot (for logging)
declare -A CPU_TICKS           # pid -> last cumulative CPU-time ticks
declare -A CPU_NANO            # pid -> last sample wall-clock (ns)
declare -A MEM_HITS            # pid -> consecutive high-memory breaches
declare -A MEM_PIDMAP          # pid -> name snapshot (for logging)

# Timestamped logging to stdout AND /var/log/sentinel.log
log() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] ${1}"
    printf '%s\n' "$msg" >> "$LOG_FILE"
    printf '%s\n' "$msg" >&2
}

die()   { log "FATAL: ${1}"; exit 1; }

# Lightweight actions that should work even without root (no logging side effects).
case "${1:-}" in
    --version) echo "${SENTINEL_NAME} v${SENTINEL_VERSION}"; exit 0 ;;
    --help|-h) cat <<HLP
${SENTINEL_NAME} v${SENTINEL_VERSION} — miner & rogue-process watchdog (made by IamGunpoint)

Usage (run as root):
  sudo ${0##*/}                  # install systemd service (24/7) and start monitoring
  sudo ${0##*/} --install        # install + enable + start the service
  sudo ${0##*/} --status         # show service status
  sudo ${0##*/} --diagnose       # print top CPU/RAM consumers + status + log
  sudo ${0##*/} --uninstall      # stop, disable, remove the service
  ${0##*/} --version             # print version
HLP
        exit 0 ;;
esac

# Require root
[[ $EUID -ne 0 ]] && die "This script MUST run as root (EUid=$EUID). Use: sudo $0"

# Ensure we are not already running (flock on a lock file)
exec 9>"$LOCK"
if ! flock -n 9; then
    die "Another instance of ${SENTINEL_NAME} is already running (lock: $LOCK)."
fi

# Absolute path to self (so the unit file can reference us reliably)
SELF="$(readlink -f "${BASH_SOURCE[0]}")"

# ────────────────────────────────────────────────────────────────────────────
# SECTION 3 : SAFETY — IMMUNE PROCESSES
# ────────────────────────────────────────────────────────────────────────────
# True if a pid/name must NEVER be touched (regardless of any match).
is_immune() {
    local name="$1" pid="$2"
    # Never kill ourselves, our shell, or our parent lineage.
    [[ "$pid" == "$$" ]] && return 0
    [[ "$name" == "$SENTINEL_NAME" || "$name" == "sentineld" ]] && return 0
    [[ "$name" == "bash" || "$name" == "sh" || "$name" == "dash" ]] && return 0
    # Named safe list / kernel / PID 1
    for s in "${SAFE_CPUS[@]}"; do
        [[ "$name" == ${s} ]] && return 0
    done
    # Kernel threads (comm live in brackets [] — always untouchable)
    [[ "$name" == *"["*"]" ]] && return 0
    # Kworkers/kernel threads by name
    case "$name" in
        kthreadd|kworker*|ksoftirqd*|kswapd*|kblockd*|md*|kdmflush*|kcompactd*)
            return 0 ;;
    esac
    # PID 1 and the init/session that spawned us can never be reaped.
    [[ "$pid" == "1" || "$pid" == "2" ]] && return 0
    return 1
}

# ────────────────────────────────────────────────────────────────────────────
# SECTION 4 : TARGETED TERMINATION
# ────────────────────────────────────────────────────────────────────────────
# kill a single pid, escalating SIGTERM -> SIGKILL, with audit logging.
# reason: human-readable justification written to the log.
terminate() {
    local pid="$1" name="$2" reason="$3"
    is_immune "$name" "$pid" && { log "SKIP immune pid=$pid ($name)"; return; }
    if ! kill -0 "$pid" 2>/dev/null; then return; fi   # already gone
    # Give it SIGTERM, brief grace, then SIGKILL if it survives.
    kill -TERM "$pid" 2>/dev/null
    for i in 1 2 3 4 5; do
        kill -0 "$pid" 2>/dev/null || { log "TERMINATED pid=$pid ($name) — $reason"; return; }
        sleep 0.2
    done
    kill -KILL "$pid" 2>/dev/null
    log "TERMINATED pid=$pid ($name) with SIGKILL — $reason"
}



# True if a process should be treated as TRUSTED (never a miner target):
#   * kernel threads / processes whose exe we cannot read
#   * binaries in distro-managed paths (/usr/bin, /usr/sbin, /bin, /sbin, /usr/lib*)
#   * /usr/local and /opt are NOT trusted (common drop zones for miners)
is_trusted_exe_check() {
    local pid="$1" exe
    exe=$(readlink -f "/proc/${pid}/exe" 2>/dev/null)
    [[ -z "$exe" ]] && return 0              # kernel thread / unreadable -> treat as trusted
    case "$exe" in
        /usr/bin/*|/usr/sbin/*|/bin/*|/sbin/*|\
        /usr/libexec/*|/usr/lib/*|/usr/lib64/*|/lib/*|/lib64/*) return 0 ;;
        *) return 1 ;;
    esac
}

# ────────────────────────────────────────────────────────────────────────────
# SECTION 5 : TARGET IDENTIFICATION  — SERVICE 1 : MINER LIST MATCH (host)
# ────────────────────────────────────────────────────────────────────────────
# Scan every host process. If its executable name OR its full command line
# matches the compiled miner signatures -> terminate it.
check_miner_names() {
    # -eo args includes the full command line; comm is truncated exec name.
    local line pid name argline lname larg trusted=0
    while IFS= read -r line; do
        pid=$(awk '{print $1}' <<<"$line")
        name=$(awk '{print $2}' <<<"$line")
        argline=$(cut -d' ' -f3- <<<"$line")
        is_immune "$name" "$pid" && continue

        lname=${name,,}
        larg=${argline,,}

        # SAFETY SPINE: a *trusted* (distro-managed / kernel / no-exe) process is
        # NEVER a miner target. Coin miners are always dropped binaries living in
        # /tmp, /dev/shm, ~, /var/tmp or user-installed /usr/local paths. This
        # single check is what stops us from ever killing agetty, edac-poller,
        # systemd, kernel threads, or any legitimate service.
        if is_trusted_exe_check "$pid"; then
            [[ "$lname" =~ $MINER_NAME_RE ]] && {
                # Even a trusted location is killable if the *binary name* is an
                # unambiguous miner (covers legit-looking installs of real miners).
                case "$lname" in
                    xmrig*|ethminer*|ccminer*|cgminer*|sgminer*|minerd*|bfgminer*|claymore*|phoenixminer*|nanominer*|t-rex*|lolminer*|teamredminer*|nbminer*|gminer*|rigel*|wildrig*|kawpowminer*|xmr-stak*|nheqminer*|cpuminer*)
                        terminate "$pid" "$name" "Matched known miner binary name (trusted path)"
                        continue ;;
                esac
            }
            continue
        fi

        # Untrusted executable -> eligible for BOTH name and cmdline matching.
        if [[ "$lname" =~ $MINER_NAME_RE ]] || [[ "$larg" =~ $MINER_NAME_RE ]] \
           || [[ "$larg" =~ $MINER_STRING_RE ]]; then
            terminate "$pid" "$name" "Matched known miner (name/cmdline) in untrusted location"
        elif [[ "$KILL_SUSPICIOUS_PATH" == "1" ]] && is_suspicious_path "$pid" \
              && [[ "$lname" != "$SENTINEL_NAME" ]]; then
            terminate "$pid" "$name" "Unknown binary in suspicious path /tmp|/dev/shm|/var/tmp"
        fi
    done < <(ps -eo pid=,comm=,args=)
}

# ────────────────────────────────────────────────────────────────────────────
# SECTION 6 : TARGET IDENTIFICATION — SERVICE 2 : HIGH-RESOURCE (CPU + MEM)
# ----------------------------------------------------------------------------
# WHY WE SAMPLE /proc AND NOT `ps %CPU`:
#   * GNU `ps %CPU` is the AVERAGE over a process's whole lifetime, so a rogue
#     that only started pegging a moment ago, or that ran fine for an hour and
#     then spiked, shows a misleadingly low value. It also divides across cores.
#   * Here we read the process's CUMULATIVE cpu time from /proc/<pid>/stat each
#     poll and divide the DELTA by our own wall-clock delta. That gives the
#     fraction of a SINGLE core it is burning RIGHT NOW (can exceed 100% for
#     multithreaded), so a pinned core is caught on any core count.
#   * A memory monitor (RSS % of total RAM) is added so RAM hogs are caught too.
# ----------------------------------------------------------------------------
# Fraction (0-100+) of a single core a process used over the polling gap.
cpu_percent_since() {
    local d=$1 dn=$2
    [[ "$dn" -le 0 ]] && { echo 0; return; }
    awk -v d="$d" -v dn="$dn" -v hz="$HZ" 'BEGIN{ printf "%d", (d * 1000000000.0 * 100.0) / (hz * dn) }'
}

# High-CPU monitor — core-count independent, instantaneous.
check_high_cpu() {
    local line pid name now_ns prev_ns cur prev d dn percent
    now_ns=$(date +%s%N)
    while IFS= read -r line; do
        pid=$(awk '{print $1}' <<<"$line")
        name=$(awk '{print $2}' <<<"$line")

        cur=$(read_cpu_ticks "$pid")
        [[ -z "$cur" ]] && { unset CPU_TICKS["$pid"] CPU_NANO["$pid"]; continue; }

        prev=${CPU_TICKS[$pid]:-}; prev_ns=${CPU_NANO[$pid]:-}
        if [[ -z "$prev" ]]; then          # first observation: just baseline it
            CPU_TICKS[$pid]=$cur; CPU_NANO[$pid]=$now_ns; continue
        fi
        d=$((cur - prev)); [[ "$d" -lt 0 ]] && d=0
        dn=$((now_ns - prev_ns))
        percent=$(cpu_percent_since "$d" "$dn")
        CPU_TICKS[$pid]=$cur; CPU_NANO[$pid]=$now_ns

        if (( percent > CPU_PERCENT_THRESHOLD )); then
            local n=${CPU_HITS[$pid]:-0}; ((n++)); CPU_HITS[$pid]=$n; CPU_PIDMAP[$pid]="$name"
            if (( n >= SAMPLES )); then
                # Respect the safe list UNLESS the process is untrusted.
                if ! would_terminate_hog "$pid" "$name"; then
                    unset CPU_HITS["$pid"]; continue
                fi
                terminate "$pid" "$name" \
                    "Exceeded ${CPU_PERCENT_THRESHOLD}% of a core (${percent}%) sustained >${CPU_SUSTAIN_SECONDS}s"
                unset CPU_HITS["$pid"] CPU_PIDMAP["$pid"] CPU_TICKS["$pid"] CPU_NANO["$pid"]
            fi
        else
            unset CPU_HITS["$pid"] CPU_PIDMAP["$pid"]
        fi
    done < <(ps -eo pid=,comm=)
}

# High-memory monitor — terminate any process holding >MEM_PERCENT_THRESHOLD %
# of total RAM for >= MEM_SUSTAIN_SECONDS. Gated by KILL_MEM_HOGS.
check_high_mem() {
    [[ "$KILL_MEM_HOGS" == "1" ]] || return
    local line pid name rss_kb rss_percent
    local mem_total_kb
    mem_total_kb=$(awk '/MemTotal:/ { print $2 }' /proc/meminfo 2>/dev/null)
    [[ -n "$mem_total_kb" ]] || return
    while IFS= read -r line; do
        pid=$(awk '{print $1}' <<<"$line")
        name=$(awk '{print $2}' <<<"$line")
        rss_kb=$(read_rss_kb "$pid"); rss_kb=${rss_kb:-0}
        rss_percent=$(awk -v r="$rss_kb" -v t="$mem_total_kb" 'BEGIN{ printf "%d", (r * 100.0) / t }')
        if (( rss_percent > MEM_PERCENT_THRESHOLD )); then
            local n=${MEM_HITS["$pid"]:-0}; ((n++)); MEM_HITS["$pid"]=$n; MEM_PIDMAP["$pid"]="$name"
            if (( n >= MEM_SAMPLES )); then
                if ! would_terminate_hog "$pid" "$name"; then
                    unset MEM_HITS["$pid"]; continue
                fi
                terminate "$pid" "$name" \
                    "Exceeded ${MEM_PERCENT_THRESHOLD}% RAM (${rss_percent}% ~ ${rss_kb} kB) sustained >${MEM_SUSTAIN_SECONDS}s"
                unset MEM_HITS["$pid"] MEM_PIDMAP["$pid"]
            fi
        else
            unset MEM_HITS["$pid"] MEM_PIDMAP["$pid"]
        fi
    done < <(ps -eo pid=,comm=)
}


# ────────────────────────────────────────────────────────────────────────────
# SECTION 7 : TARGET IDENTIFICATION — SERVICE 3 : KVM/QEMU VIRTUALIZATION
# ────────────────────────────────────────────────────────────────────────────
# Flag any KVM/QEMU VM process at INITIATION. Hardware-assisted VMs are the
# preferred way to run a mining rig, so we terminate them immediately unless
# the guest name carries an ALLOW string.
check_kvm_qemu() {
    local pid name argline ok=0 allow
    while IFS= read -r line; do
        pid=$(awk '{print $1}' <<<"$line")
        name=$(awk '{print $2}' <<<"$line")
        argline=$(cut -d' ' -f3- <<<"$line")
        is_immune "$name" "$pid" && continue

        # Allowed guest? (check allow substrings against the arg line)
        for a in "${QEMU_ALLOW_SUBSTRINGS[@]}"; do
            [[ "$argline" == *"$a"* ]] && { ok=1; break; }
        done
        [[ "$ok" == "1" ]] && continue

        terminate "$pid" "$name" \
            "KVM/QEMU virtualization process detected (prevent hardware-assisted mining rig)"
    done < <(ps -eo pid=,comm=,args= | awk '$2 ~ /^qemu|^kvm/ || $2 ~ /qemu-system/')
}

# ────────────────────────────────────────────────────────────────────────────
# SECTION 8 : TARGET IDENTIFICATION — SERVICE 4 : CONTAINER SCAN
# ----------------------------------------------------------------------------
# Enter each running container's PID namespace with `nsenter` and scan the
# processes *inside* it against the SAME miner / high-CPU signature list.
# We kill ONLY the offending inner PID, never the container runtime itself,
# so legitimate workloads in the same container keep running.
#   * Docker  : `docker ps -q` + `docker inspect` for PID -> nsenter -t <pid> -p
#   * LXC     : `lxc list -c n` (name) -> lxc exec ... or nsenter via host pid
# (Both runtimes are optional; we degrade gracefully to just host monitoring.)
# ────────────────────────────────────────────────────────────────────────────
# Drop-in scanner body that is executed INSIDE a target container's PID
# namespace. $1 = runtime label (docker/lxc), used only for the log message.
# Matching references the exported MINER_NAME_RE / MINER_STRING_RE env vars.
scan_namespace_body() {
    local label="$1" nmre="$MINER_NAME_RE" stre="$MINER_STRING_RE"
    local lc la
    while read -r p c a; do
        [[ -r "/proc/${p}/comm" ]] || continue     # process must be in this ns
        [[ "${c}" == "init" || "${c}" == "systemd" ]] && continue
        lc="${c,,}"; la="${a,,}"
        # name-only match (fast) or full-command-line match (catches renames)
        if [[ "$lc" =~ ${nmre} ]] || [[ "$la" =~ ${nmre} ]] || [[ "$la" =~ ${stre} ]]; then
            kill -9 "$p" 2>/dev/null &&
                echo "${label}(ns) killed $p ($c) — matched known miner signature"
        fi
    done < <(ps -eo pid=,comm=,args= 2>/dev/null)
}
export -f scan_namespace_body

check_containers() {
    # ---- Docker: inspect host PID of each container, nsenter its namespace ----
    if command -v docker >/dev/null 2>&1; then
        local cid pid
        while IFS= read -r cid; do
            [[ -z "$cid" ]] && continue
            pid=$(docker inspect -f '{{.State.Pid}}' "$cid" 2>/dev/null)
            [[ -z "$pid" || "$pid" == "0" ]] && continue
            if command -v nsenter >/dev/null 2>&1; then
                nsenter -t "$pid" -p -m -- \
                    bash -c 'scan_namespace_body docker' \
                    2>/dev/null | while IFS= read -r line; do
                        log "CONTAINER: ${line}"
                    done
            fi
        done < <(docker ps -q 2>/dev/null)
    fi

    # ---- LXC: exec a scan shell inside each running container ----
    if command -v lxc >/dev/null 2>&1; then
        local ct
        while IFS= read -r ct; do
            [[ -z "$ct" ]] && continue
            lxc exec "$ct" -- sh -c 'scan_namespace_body lxc' \
                2>/dev/null | while IFS= read -r line; do
                    log "CONTAINER: ${line}"
                done
        done < <(lxc list -cn 2>/dev/null | awk 'NR>1{print $1}')
    fi
}

# ────────────────────────────────────────────────────────────────────────────
# SECTION 9 : PERSISTENCE — SYSTEMD UNIT AUTOMATION
# ----------------------------------------------------------------------------
# If not already running as a systemd service, generate a hardened unit file,
# enable + manifest it, and re-exec ourselves under systemd so we survive
# reboots and are supervised/auto-restarted.
# ────────────────────────────────────────────────────────────────────────────
ensure_systemd_service() {
    local unit="/etc/systemd/system/${SENTINEL_NAME}.service"

    # Already a systemd service? Detection: we are pid 1's child & unit member.
    if systemctl --version >/dev/null 2>&1 \
       && [[ -n "${INVOCATION_ID:-}" ]]; then
        return 0                        # already supervised — do nothing
    fi

    command -v systemctl >/dev/null 2>&1 || {
        log "WARN: systemctl not found; running in foreground only."
        return 0
    }

    log "Persistence: installing systemd unit $unit"
    cat > "$unit" <<UNIT
[Unit]
Description=${SENTINEL_NAME} - Cryptocurrency Miner & Rogue-Process Watchdog
After=network.target

[Service]
Type=simple
ExecStart=${SELF}
Restart=always
RestartSec=3
# Tighten security (best-effort; safe on modern systemd):
# NoNewPrivileges=true
# ProtectSystem=full
Environment=POLL_INTERVAL=${POLL_INTERVAL}
[Install]
WantedBy=multi-user.target
UNIT

    chmod 644 "$unit"
    systemctl daemon-reload
    systemctl daemon-reload
    systemctl enable "$SENTINEL_NAME" >/dev/null 2>&1
    systemctl start "$SENTINEL_NAME" >/dev/null 2>&1
    if systemctl is-active --quiet "$SENTINEL_NAME" 2>/dev/null; then
        log "Persistence: ${SENTINEL_NAME}.service is ACTIVE (auto-restart on boot)."
    else
        log "WARN: ${SENTINEL_NAME}.service did NOT start — check: journalctl -u ${SENTINEL_NAME} -n 40"
    fi

    # Re-exec under systemd so THIS shell becomes the supervised child; if the
    # unit already started us, fall through.
    if [[ "${INVOCATION_ID:-}" == "" && "$PPID" != "0" ]]; then
        log "Persistence: handing control to systemd (sentinel.service)."
        exit 0
    fi
}


# ────────────────────────────────────────────────────────────────────────────
# SECTION 10 : MAINTENANCE — uninstall & diagnose helpers
# ────────────────────────────────────────────────────────────────────────────
uninstall_service() {
    log "Uninstall: stopping + disabling ${SENTINEL_NAME}.service"
    systemctl stop "$SENTINEL_NAME" 2>/dev/null
    systemctl disable "$SENTINEL_NAME" 2>/dev/null
    rm -f "/etc/systemd/system/${SENTINEL_NAME}.service"
    systemctl daemon-reload 2>/dev/null
    log "Uninstall: removed ${SENTINEL_NAME}.service"
}

# Print the biggest CPU/RAM consumers, service state, and recent log so you can
# identify exactly what is eating the box BEFORE the watchdog terminates it.
diagnose() {
    echo "=== ${SENTINEL_NAME} diagnose v${SENTINEL_VERSION} ==="
    echo "--- Top CPU consumers (pid, %cpu, %mem, RSS, name, args) ---"
    ps -eo pid=,pcpu=,pmem=,rss=,comm=,args= --sort=-pcpu | head -n 12
    echo
    echo "--- Top memory consumers ---"
    ps -eo pid=,pcpu=,pmem=,rss=,comm=,args= --sort=-rss | head -n 12
    echo
    echo "--- Service status ---"
    systemctl status "$SENTINEL_NAME" --no-pager 2>/dev/null | head -n 16 || echo "(not a service)"
    echo
    echo "--- Last 20 log lines ---"
    tail -n 20 "$LOG_FILE" 2>/dev/null || echo "(no log yet — run as root and it appears)"
}

# ────────────────────────────────────────────────────────────────────────────
# SECTION 10 : STARTUP / BANNER
# ────────────────────────────────────────────────────────────────────────────
banner() {
    log "╔══════════════════════════════════════════════════════════════╗"
    log "║  ${SENTINEL_NAME} v${SENTINEL_VERSION}  —  Miner & Rogue-Process Watchdog          ║"
    log "║  made by IamGunpoint                                        ║"
    log "║  Log: ${LOG_FILE}                                            ║"
    log "║  CPU threshold: >${CPU_PERCENT_THRESHOLD}% of a core / ${CPU_SUSTAIN_SECONDS}s  | interval ${POLL_INTERVAL}s ║"
    log "║  RAM threshold: >${MEM_PERCENT_THRESHOLD}% of RAM / ${MEM_SUSTAIN_SECONDS}s  (kill=${KILL_MEM_HOGS})           ║"
    log "╚══════════════════════════════════════════════════════════════╝"
}

# ────────────────────────────────────────────────────────────────────────────
# SECTION 11 : MAIN MONITORING LOOP  (infinite, sub-second)
# ────────────────────────────────────────────────────────────────────────────
main() {
    case "${1:-}" in
        --install)   ensure_systemd_service; exit $? ;;
        --uninstall) uninstall_service; exit $? ;;
        --status)    systemctl status "$SENTINEL_NAME" --no-pager 2>/dev/null; exit $? ;;
        --version)   echo "${SENTINEL_NAME} v${SENTINEL_VERSION}"; exit 0 ;;
        --diagnose)  diagnose; exit $? ;;
        --foreground|"")  : ;;
        *) echo "Unknown option: ${1} (try --install, --status, --diagnose, --foreground)"; exit 2 ;;
    esac
    ensure_systemd_service
    banner
    log "START: ${SENTINEL_NAME} watchdog armed (pid $$)."

    local loop=0
    while true; do
        # 1. Known miner list (host) — most likely threat, cheap via ps.
        check_miner_names

        # 2. High-resource rogue-process monitors (CPU + memory).
        check_high_cpu
        check_high_mem

        # 3. KVM/QEMU virtualization guard (only if qemu/kvm binaries present).
        if command -v qemu-system-x86_64 >/dev/null 2>&1 \
           || pgrep -x qemu-system-x86_64 >/dev/null 2>&1; then
            check_kvm_qemu
        fi

        # 4. Container namespace scan — refresh every N loops to bound fork cost.
        (( loop++ ))
        if (( loop % CONTAINER_REFRESH_EVERY == 0 )); then
            check_containers
        fi

        # Sub-second sleep to keep reaction time near-instant.
        sleep "$POLL_INTERVAL"

        # Periodic watchdog heartbeat (every ~1 min) so admins know it's alive.
        if (( loop % 120 == 0 )); then
            log "HEARTBEAT: ${SENTINEL_NAME} running — $(date '+%F %T') [loop $loop]"
        fi
    done
}

main "$@"
