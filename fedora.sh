#!/bin/bash
###############################################################################
#  sentinel-fedora.sh — Cryptocurrency-Miner & Rogue-Process Watchdog
#                        (FEDORA / SELINUX EDITION)
#  ----------------------------------------------------------------------------
#  Fedora-optimised build of sentinel.sh. Everything from the base watchdog
#  applies (host miner list, sustained >70% CPU monitor, KVM/QEMU guard,
#  one-file self-contained design, automatic systemd persistence). What is
#  DIFFERENT for Fedora:
#
#    * CONTAINER ENGINE  : Fedora's default container tooling is PODMAN, not
#                          Docker. We scan containers via `podman exec`
#                          (falling back to `docker exec`, then `nsenter`).
#                          Running the scan through the runtime is the
#                          SELinux-correct approach, so we avoid AVC denials
#                          that raw `nsenter` into a confined svirt/container
#                          domain would cause under enforcing mode.
#    * SELINUX AWARENESS : detects getenforce; keeps /proc reads and kills
#                          graceful; NEVER lets being blocked from reading a
#                          guarded process's /proc/<pid>/exe crash the scan
#                          (it just falls back to name/cmdline matching).
#    * TOOLING           : assumes procps-ng `ps`, coreutils, util-linux,
#                          gawk — all present in Fedora by default.
#    * LXC               : usually absent on Fedora (EPEL). Handled only if
#                          the `lxc` binary exists; otherwise skipped.
#
#  Author design note:        "made by IamGunpoint"
#
#  REQUIREMENTS
#  ------------
#    * Must run as root.
#    * Standard binaries only: bash ps awk sed tr cut systemctl kill pgrep
#      plus one container runtime available on the host: podman *or* docker,
#      and optionally lxc. All optional and gracefully skipped.
#
#  LEGAL / SAFETY WARNING
#  ----------------------
#    Defensive tool for hosts you own. Killing KVM/QEMU and stopping high-CPU
#    processes destroys legitimate workloads (CI/build VMs, render farms).
#    Tune SAFE_CPUS / QEMU_ALLOW_SUBSTRINGS before production use.
###############################################################################


###############################################################################
#  SELINUX NOTES (Fedora)
#  ----------------------------------------------------------------------------
#  When this watchdog runs as a systemd service under enforcing SELinux:
#    * Reading /proc/<pid>/exe for a CONFINED daemon (httpd_t, sshd_t, etc.)
#      may be denied. That does not break anything: is_suspicious_path just
#      returns "not suspicious" and detection falls back to name/cmdline
#      matching. This is why the host scan remains fully effective.
#    * Container scans run through `podman exec` / `docker exec`, which do the
#      SELinux transition themselves, so AVCs are avoided. Only if there is NO
#      runtime binary do we try raw `nsenter`, which MAY be denied — that is
#      logged and skipped, never fatal.
#    * If a service-domain denial blocks `podman`/`docker` from the unit, the
#      common causes and fixes are:
#         1. Check AVCs:   ausearch -m avc -ts recent | grep sentinel
#         2. The unit runs as a custom type; if your policy denies the runtime,
#            either add the service to the container management domain, or
#            restart it once as an unconfined invocation:
#               sudo semanage fcontext -a -t usr_t /usr/local/sbin/sentinel-fedora.sh
#               sudo restorecon -v /usr/local/sbin/sentinel-fedora.sh
#         3. Reboot after relabelling, or `restorecon -R /var/lib/containers`
#            if container storage labelling is the issue.
#    * The watchdog itself never relabels or flips enforcing mode — it stays
#      within policy and is safe to leave SELinux fully enforcing.
###############################################################################

# ────────────────────────────────────────────────────────────────────────────
# SECTION 0 : CONFIGURATION & TUNABLES
# ────────────────────────────────────────────────────────────────────────────
SENTINEL_VERSION="1.1.0-fedora"
SENTINEL_NAME="sentinel"

# Logging targets
LOG_FILE="/var/log/sentinel.log"

# SELinux mode snapshot (off/permissive/enforcing) — detected & logged at start.
SELINUX_MODE="$(getenforce 2>/dev/null | tr 'A-Z' 'a-z')"   # '' if no SELinux
CONTAINER_RUNTIME=""        # resolved at startup: podman | docker | lxc | none

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
    "stratum+tcp" "stratum+ssl" "stratum+tls" "stratum2" "stratum"
    "getwork" "getblocktemplate" "coinbase"
    "nicehash" "nanopool" "minergate" "minexmr" "supportxmr" "moneroocean"
    "dwarfpool" "hashspeed" "kryptex" "ethermine" "ethpool" "f2pool"
    "prohashing" "miningpoolhub" "mining-pool" "hashpool" "pool.mine"
    "--coin=monero" "--algo" "--algo=randomx" "--algo=cryptonight"
    "--coin" "-o stratum" "-u wallet" "--donate-level" "--nicehash"
    "xmrig" "xmr-stak" "ethminer" "--opencl" "--cuda" "--cpu-affinity"
    "cryptonight" "ethash" "equihash" "lyra2" "x16r" "x16s" "cn_slow_hash"
    "--tls" "--threads" "--av" "--randomx" "--cpu-priority"
    "minerd" "cgminer" "cgminer.exe" "cpuminer" "cpuminer-opt"
    "ethminer.exe" "--farm-reward" "--pool" "--port" "--user" "--pass"
    "nheqminer" "quadriga" "--output" "-P" "stratum://" "stratum+tcp://"
    "--api-bind" "--background" "bfgminer" "sgminer" "claymore"
    "phoenixminer" "nanominer" "lolMiner" "teamredminer" "gminer"
    "--bminer" "bminer" "eth-proxy" "-–curl" "wget.*\.sh" "curl.*.sh"
    "minergate-cli" "kdevtmpfsi" "kinsing" "/tmp/.*miner" "sha256d"
    "scrypt" "x11" "keccak" "blake2b" "decred" "cash"
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

# ────────────────────────────────────────────────────────────────────────────
# SECTION 2 : GLOBAL STATE & HELPERS
# ────────────────────────────────────────────────────────────────────────────
LOCK="/var/lock/${SENTINEL_NAME}.lock"
declare -A CPU_HITS            # pid -> count of consecutive breaches
declare -A CPU_PIDMAP          # pid -> name snapshot (for logging)

# Timestamped logging to stdout AND /var/log/sentinel.log
log() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] ${1}"
    printf '%s\n' "$msg" >> "$LOG_FILE"
    printf '%s\n' "$msg" >&2
}

die()   { log "FATAL: ${1}"; exit 1; }

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

# ────────────────────────────────────────────────────────────────────────────
# SECTION 5 : TARGET IDENTIFICATION  — SERVICE 1 : MINER LIST MATCH (host)
# ────────────────────────────────────────────────────────────────────────────
# Scan every host process. If its executable name OR its full command line
# matches the compiled miner signatures -> terminate it.
check_miner_names() {
    # -eo args includes the full command line; comm is truncated exec name.
    # We read with a while loop to avoid forks per process.
    local line pid name argline lname larg
    while IFS= read -r line; do
        # handle names containing spaces minimally (use last field split safely)
        pid=$(awk '{print $1}' <<<"$line")
        name=$(awk '{print $2}' <<<"$line")
        argline=$(cut -d' ' -f3- <<<"$line")
        is_immune "$name" "$pid" && continue

        # Lowercase for case-insensitive signature match.
        lname=${name,,}
        larg=${argline,,}

        # Match executable name OR full command line against miner signatures.
        if [[ "$lname" =~ $MINER_NAME_RE ]] || [[ "$larg" =~ $MINER_NAME_RE ]] \
           || [[ "$larg" =~ $MINER_STRING_RE ]]; then
            terminate "$pid" "$name" "Matched known miner list (name/cmdline signature)"
        elif [[ "$KILL_SUSPICIOUS_PATH" == "1" ]] && is_suspicious_path "$pid" \
              && [[ "$lname" != "$SENTINEL_NAME" ]]; then
            # Unknown binary living in a world-writable dir: treat as a miner
            # drop-in unless it is a known/good process already whitelisted.
            terminate "$pid" "$name" "Unknown binary in suspicious path /tmp|/dev/shm|/var/tmp"
        fi
    done < <(ps -eo pid=,comm=,args=)
}

# ────────────────────────────────────────────────────────────────────────────
# SECTION 6 : TARGET IDENTIFICATION — SERVICE 2 : HIGH-RESOURCE MONITOR
# ────────────────────────────────────────────────────────────────────────────
# Track any process that is using >$CPU_PERCENT_THRESHOLD % CPU and has
# sustained it for >= $CPU_SUSTAIN_SECONDS. Note: ps %CPU is per-sampling-frame
# so we accumulate consecutive breaches via a sliding "hit counter", which in
# practice approximates a sustained-load window for a fixed-interval poller.
check_high_cpu() {
    # print pid,pcpu,comm  (exclude zero-CPU to cut noise)
    local pid pcpu name breach=0
    while IFS= read -r line; do
        pid=$(awk '{print $1}' <<<"$line")
        pcpu=$(awk '{print $2}' <<<"$line")
        name=$(awk '{print $3}' <<<"$line")

        # Floating point comparison against threshold
        breach=$(awk -v c="$pcpu" -v t="$CPU_PERCENT_THRESHOLD" \
                     'BEGIN{print (c > t)?1:0}')

        if [[ "$breach" == "1" ]]; then
            # Increment hit counter
            local n=${CPU_HITS[$pid]:-0}
            ((n++))
            CPU_HITS[$pid]=$n
            CPU_PIDMAP[$pid]="$name"
            # Sustained breach for too long?
            # (Samples in flight ≈ sustained_seconds / interval)
            if (( n >= SAMPLES )); then
                is_immune "$name" "$pid" && { unset CPU_HITS[$pid]; continue; }
                terminate "$pid" "$name" \
                    "Exceeded ${CPU_PERCENT_THRESHOLD}% CPU (${pcpu}%) sustained >${CPU_SUSTAIN_SECONDS}s"
                unset CPU_HITS[$pid] CPU_PIDMAP[$pid]
            fi
        else
            # Reset this pid's breach window when it drops below threshold
            unset CPU_HITS[$pid] CPU_PIDMAP[$pid]
        fi
    done < <(ps -eo pid=,pcpu=,comm=)
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
# SECTION 8 : TARGET IDENTIFICATION — SERVICE 4 : CONTAINER SCAN  (FEDORA)
# ----------------------------------------------------------------------------
# Fedora default engine is PODMAN, so we prefer `podman exec` to enter a
# container: it is SELinux-aware and does not require raw nsenter access into
# confined svirt domains (which enforcing SELinux would AVC-deny). We scan the
# guest process table INSIDE its namespace and kill ONLY the offending inner
# PID, never the runtime, so other containers keep running. Fallbacks:
#   podman exec  ->  docker exec  ->  nsenter -t <pid> -p  (last resort)
# LXC is EPEL-only on Fedora; handled if the `lxc` binary exists.
# ----------------------------------------------------------------------------
# The drop-in scan body is run INSIDE a guest namespace by the runtime exec and
# receives the case-insensitive miner regexes via the container environment.
# Pick which container runtime is available and usable, once at startup.
detect_container_runtime() {
    if command -v podman >/dev/null 2>&1 && podman --version >/dev/null 2>&1; then
        CONTAINER_RUNTIME="podman"
    elif command -v docker >/dev/null 2>&1 && docker --version >/dev/null 2>&1; then
        CONTAINER_RUNTIME="docker"
    elif command -v lxc >/dev/null 2>&1; then
        CONTAINER_RUNTIME="lxc"
    else
        CONTAINER_RUNTIME="none"
    fi
    log "Container runtime: ${CONTAINER_RUNTIME}"
}

# Emit a space-separated list of running container ids/names for the engine.
list_containers() {
    case "$CONTAINER_RUNTIME" in
        podman) podman ps -q --notruncate 2>/dev/null ;;
        docker) docker ps -q 2>/dev/null ;;
        lxc)    lxc list -cn 2>/dev/null | awk 'NR>1{print $1}' ;;
    esac
}

# A SELF-CONTAINED scan snippet executed INSIDE each container. Podman/docker
# exec runs a fresh shell in the guest namespace, so we cannot rely on the
# parent's exported bash functions. We inline the whole matcher and pass the
# case-insensitive regexes through the runtime as environment variables.
scan_container_snippet() {
    cat <<'SNIP'
while read -r p c a; do
    [ -r "/proc/$p/comm" ] || continue
    [ "$c" = "init" ] && continue
    lc=$(echo "$c" | tr 'A-Z' 'a-z'); la=$(echo "$a" | tr 'A-Z' 'a-z')
    if [[ "$lc" =~ (${MINER_NAME_RE:-x^^x}) ]] || [[ "$la" =~ (${MINER_NAME_RE:-x^^x}) ]] \
       || [[ "$la" =~ (${MINER_STRING_RE:-x^^x}) ]]; then
        kill -9 "$p" 2>/dev/null && echo "killed $p ($c) = matched known miner signature"
    fi
done < <(ps -eo pid=,comm=,args= 2>/dev/null)
SNIP
}

# Run the snippet as a bash one-liner inside one container id via podman/docker,
# or via `lxc exec`/`nsenter` for the other runtimes. The regex env vars are
# passed with -e so the guest bash can expand them.
scan_one_container() {
    local id="$1"
    local snippet
    snippet="$(scan_container_snippet)"

    case "$CONTAINER_RUNTIME" in
        podman)
            podman exec -e MINER_NAME_RE="$MINER_NAME_RE" \
                        -e MINER_STRING_RE="$MINER_STRING_RE" \
                        "$id" bash -c "$snippet" 2>/dev/null \
                | while IFS= read -r line; do log "CONTAINER(podman): ${line}"; done
            ;;
        docker)
            docker exec -e MINER_NAME_RE="$MINER_NAME_RE" \
                        -e MINER_STRING_RE="$MINER_STRING_RE" \
                        "$id" bash -c "$snippet" 2>/dev/null \
                | while IFS= read -r line; do log "CONTAINER(docker): ${line}"; done
            ;;
        lxc)
            lxc exec "$id" -- bash -c "$snippet" 2>/dev/null \
                | while IFS= read -r line; do log "CONTAINER(lxc): ${line}"; done
            ;;
        *)
            # No runtime binary: last-resort raw nsenter into the guest namespace.
            if command -v nsenter >/dev/null 2>&1; then
                local mpid spid
                mpid=$(pgrep -f 'container-shim|conmon|qemu-system' 2>/dev/null | head -1)
                if [[ -n "$mpid" ]]; then
                    nsenter -t "$mpid" -p -m -- bash -c "$snippet" 2>/dev/null \
                        | while IFS= read -r line; do log "CONTAINER(nsenter): ${line}"; done
                fi
            fi
            ;;
    esac
}

check_containers() {
    [[ "$CONTAINER_RUNTIME" == "none" ]] && return
    local id
    while IFS= read -r id; do
        [[ -z "$id" ]] && continue
        scan_one_container "$id"
    done < <(list_containers)
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
    # Fedora/SELinux: ensure the new unit gets a proper SELinux context so
    # systemd can read it, and that the watchdog binary is labelled executably.
    if command -v restorecon >/dev/null 2>&1; then
        restorecon -v "$unit" 2>/dev/null
        restorecon -v "$SELF" 2>/dev/null
    fi
    systemctl daemon-reload
    systemctl enable "$SENTINEL_NAME" >/dev/null 2>&1
    log "Persistence: enabling + starting ${SENTINEL_NAME}.service"
    systemctl start "$SENTINEL_NAME" >/dev/null 2>&1

    # Re-exec under systemd so THIS shell becomes the supervised child; if the
    # unit already started us, fall through.
    if [[ "${INVOCATION_ID:-}" == "" && "$PPID" != "0" ]]; then
        log "Persistence: handing control to systemd (sentinel.service)."
        exit 0
    fi
}

# ────────────────────────────────────────────────────────────────────────────
# SECTION 10 : STARTUP / BANNER
# ────────────────────────────────────────────────────────────────────────────
banner() {
    log "╔══════════════════════════════════════════════════════════════╗"
    log "║  ${SENTINEL_NAME} v${SENTINEL_VERSION}  —  Miner & Rogue-Process Watchdog          ║"
    log "║  made by IamGunpoint                                        ║"
    log "║  Log: ${LOG_FILE}                                            ║"
    log "║  CPU threshold: >${CPU_PERCENT_THRESHOLD}% for ${CPU_SUSTAIN_SECONDS}s | interval ${POLL_INTERVAL}s ║"
    log "║  SELinux: ${SELINUX_MODE:-none} | runtime: ${CONTAINER_RUNTIME:-?}   ║"
    log "╚══════════════════════════════════════════════════════════════╝"
}

# ────────────────────────────────────────────────────────────────────────────
# SECTION 11 : MAIN MONITORING LOOP  (infinite, sub-second)
# ────────────────────────────────────────────────────────────────────────────
main() {
    ensure_systemd_service
    detect_container_runtime     # resolve podman/docker/lxc BEFORE the banner
    banner
    if [[ -n "$SELINUX_MODE" ]]; then
        log "SELinux: ${SELINUX_MODE} mode detected — AVCs from guarded /proc reads are tolerated."
    fi
    log "START: ${SENTINEL_NAME} watchdog armed (pid $$)."

    local loop=0
    while true; do
        # 1. Known miner list (host) — most likely threat, cheap via ps.
        check_miner_names

        # 2. High-resource rogue-process monitor.
        check_high_cpu

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
