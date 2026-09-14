#!/usr/bin/env bash
# =============================================================================
# olsr-research.sh -- single entry point for the OLSR defense research.
#
# This repository evaluates four published defenses against a blackhole /
# link-spoofing attacker in OLSR. Each defense compiles DIFFERENT src/olsr
# code, so each lives on its own git branch:
#
#     trust-defense     TRUST-OLSR     (Adnane, Bidan & de Sousa, 2013)
#     fpnt-defense      FPNT-OLSR      (Tan, Li & Dong, 2015)
#     dcfm-defense      DCFM-OLSR      (Schweitzer et al., 2025)
#     watchdog-defense  Watchdog-OLSR  (Baiad et al., 2014)
#
# Everything that differs between them is declared in ONE file,
# tools/defense.manifest, which each branch carries its own copy of. This
# script is byte-identical on every branch and reads that manifest, so you
# never have to remember which flags go with which defense -- in particular
# the two TRUST flags without which that defense is mostly switched off (see
# docs/RUNNING.md, "The TRUST default-flags trap").
#
# Commands:
#     doctor            check the toolchain, the branch and the build
#     use <defense>     switch to that defense's branch and build it
#                       (trust | fpnt | dcfm | watchdog)
#     build             (re)configure and build the current branch's harness
#     smoke             ~5 runs, a couple of minutes, proves the chain works
#     run [opts]        one dataset batch for the current defense
#     batch [opts]      reproduce the canonical dataset batches
#
# Run `./tools/olsr-research.sh help` for the full option list.
# =============================================================================

set -uo pipefail
shopt -s nullglob

# --- locate the repository ---------------------------------------------------
# Everything is derived from git, so this script works from any directory and
# from any clone path. There are no absolute paths anywhere in this file.
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || {
    echo "ERROR: not inside a git repository." >&2
    echo "       Run this from a clone of the ns-3-dev research repo." >&2
    exit 1
}
MANIFEST="$REPO_ROOT/tools/defense.manifest"
RUNNER="$REPO_ROOT/tools/run_simulations.sh"
DEFAULT_OUT_ROOT="$REPO_ROOT/datasets"

# Branch that carries each defense. This table is the only place the mapping
# from a short name to a branch name is written down.
defense_branch() {
    case "$1" in
        trust)    echo "trust-defense"    ;;
        fpnt)     echo "fpnt-defense"     ;;
        dcfm)     echo "dcfm-defense"     ;;
        watchdog) echo "watchdog-defense" ;;
        *)        return 1 ;;
    esac
}

# --- output helpers ----------------------------------------------------------
say()  { printf '%s | %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
info() { printf '  %s\n' "$*"; }
ok()   { printf '  [ ok ] %s\n' "$*"; }
# bad/warn deliberately go to stdout, not stderr: 'doctor' is a report that has
# to be readable top to bottom, and mixing the two streams shuffles the lines.
# Hard failures still use die(), which writes to stderr, and the exit code
# carries the result for anything scripting against this.
bad()  { printf '  [FAIL] %s\n' "$*"; }
warn() { printf '  [warn] %s\n' "$*"; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
rule() { printf '=======================================================================\n'; }

# --- manifest ----------------------------------------------------------------
# Sourced, not parsed: it is a tiny shell fragment of KEY=value assignments.
# Every field is documented in tools/defense.manifest itself.
load_manifest() {
    [[ -f "$MANIFEST" ]] || die "missing $MANIFEST (is this the research repo?)"
    # shellcheck source=/dev/null
    . "$MANIFEST"
    : "${DEFENSE_ID:?defense.manifest is missing DEFENSE_ID}"
    : "${DEFENSE_NAME:=$DEFENSE_ID}"
    : "${DEFENSE_BRANCH:=}"
    : "${SCRATCH_TARGET:=}"
    : "${DEFENSE_FLAGS:=}"
    : "${PAPER:=}"
    : "${BATCH_SEED_STATIC:=1}"
    : "${BATCH_SEED_MOBILE:=2000001}"
    : "${BATCH_SEED_STATIC_MIXED:=10000001}"
    : "${BATCH_SEED_MOBILE_MIXED:=12000001}"
}

current_branch() { git -C "$REPO_ROOT" rev-parse --abbrev-ref HEAD; }

# A manifest with DEFENSE_ID=none means "this branch carries no defense
# harness" -- that is master, the shared base. Nothing but `use` works there.
require_defense() {
    if [[ "$DEFENSE_ID" == "none" ]]; then
        rule
        echo "  No defense is selected on this branch ($(current_branch))."
        echo
        echo "  This branch holds the shared tooling and documentation; it is not a defense branch."
        echo "  Pick a defense to work on:"
        echo
        echo "      ./tools/olsr-research.sh use trust     # TRUST-OLSR     (Adnane et al., 2013)"
        echo "      ./tools/olsr-research.sh use fpnt      # FPNT-OLSR      (Tan et al., 2015)"
        echo "      ./tools/olsr-research.sh use dcfm      # DCFM-OLSR      (Schweitzer et al., 2025)"
        echo "      ./tools/olsr-research.sh use watchdog  # Watchdog-OLSR  (Baiad et al., 2014)"
        echo
        rule
        exit 1
    fi
}

# Locate the built harness binary. Deliberately a glob rather than a computed
# name: the ns-3 binary prefix tracks the VERSION file, which differs between
# master ("3-dev") and the release-based defense branches ("3.47"). Globbing on
# the target name is correct on all of them.
find_binary() {
    local hits=( "$REPO_ROOT/build/scratch/"*"$SCRATCH_TARGET"* )
    local f
    for f in "${hits[@]}"; do
        [[ -f "$f" && -x "$f" ]] && { echo "$f"; return 0; }
    done
    return 1
}

# The binary must be newer than every scratch source. A silently stale binary
# emits the previous revision's schema and nothing downstream notices -- this
# is the single most expensive mistake available in this project, because the
# resulting CSVs look completely plausible.
check_binary_fresh() {
    local bin="$1" src
    for src in "$REPO_ROOT/scratch/"*.cc "$REPO_ROOT/scratch/"*.h; do
        [[ -f "$src" ]] || continue
        if [[ "$src" -nt "$bin" ]]; then
            bad "stale build: $(basename "$src") is newer than the binary"
            info "run: ./tools/olsr-research.sh build"
            return 1
        fi
    done
    return 0
}

tree_is_clean() { [[ -z "$(git -C "$REPO_ROOT" status --porcelain)" ]]; }

# ns-3 publishes every module header as build/include/ns3/<name>.h, a one-line
# forwarding stub that #includes the source file by absolute path. Configure
# creates a stub that is missing but does NOT rewrite one that already exists.
#
# So when two branches install a header of the same name from different source
# paths, switching branches leaves the stub pointing at a file that no longer
# exists, and every harness that includes ns3/olsr-module.h fails to compile.
# That is exactly what happened on a fresh clone: trust-defense once installed
# model/defense/olsr-repositories.h (master still does), the other three
# branches install model/olsr-repositories.h, and "use trust" followed by any other defense broke
# the build.
#
# A stub whose target is missing can never be included successfully, so
# deleting it is always safe; configure then recreates it pointing at the file
# the current branch actually has.
prune_dangling_stubs() {
    local dir="$REPO_ROOT/build/include/ns3" f target n=0
    [[ -d "$dir" ]] || return 0
    for f in "$dir"/*.h; do
        target="$(sed -n '1s/^#include "\(\/.*\)"$/\1/p' "$f")"
        if [[ -n "$target" && ! -e "$target" ]]; then
            rm -f "$f"
            n=$(( n + 1 ))
        fi
    done
    if (( n > 0 )); then
        info "removed $n stale forwarding header(s) left behind by another branch"
    fi
    return 0
}

# =============================================================================
# doctor
# =============================================================================
cmd_doctor() {
    load_manifest
    local rc=0 branch bin
    branch="$(current_branch)"

    rule
    echo "  OLSR defense research -- environment check"
    rule
    info "repository : $REPO_ROOT"
    info "branch     : $branch"
    info "commit     : $(git -C "$REPO_ROOT" rev-parse --short HEAD)"
    info "defense    : $DEFENSE_NAME"
    [[ -n "$PAPER" ]] && info "paper      : $PAPER"
    echo

    # --- toolchain ---
    echo "Toolchain"
    if [[ -n "${BASH_VERSINFO:-}" ]] && { (( BASH_VERSINFO[0] > 4 )) || { (( BASH_VERSINFO[0] == 4 )) && (( BASH_VERSINFO[1] >= 3 )); }; }; then
        ok "bash ${BASH_VERSINFO[0]}.${BASH_VERSINFO[1]} (>= 4.3 required for 'wait -n')"
    else
        bad "bash >= 4.3 required (found ${BASH_VERSION:-unknown})"; rc=1
    fi
    local tool
    for tool in git cmake awk flock nproc; do
        if command -v "$tool" >/dev/null 2>&1; then ok "$tool"
        else bad "$tool not found in PATH"; rc=1; fi
    done
    if command -v g++ >/dev/null 2>&1 || command -v clang++ >/dev/null 2>&1; then
        ok "C++ compiler"
    else
        bad "no g++ or clang++ in PATH"; rc=1
    fi
    echo

    # --- repository state ---
    echo "Repository"
    if [[ -x "$REPO_ROOT/ns3" ]]; then ok "./ns3 is executable"
    else bad "$REPO_ROOT/ns3 is not executable"; rc=1; fi
    if tree_is_clean; then
        ok "working tree is clean"
    else
        warn "working tree has local changes -- 'use' will refuse to switch branches"
        git -C "$REPO_ROOT" status --short | sed 's/^/         /'
    fi
    echo

    if [[ "$DEFENSE_ID" == "none" ]]; then
        echo "Defense"
        info "none on this branch -- this is the shared base."
        info "Run './tools/olsr-research.sh use <trust|fpnt|dcfm|watchdog>'."
        rule
        return $rc
    fi

    # --- branch and manifest agree ---
    echo "Defense"
    if [[ -n "$DEFENSE_BRANCH" && "$DEFENSE_BRANCH" != "$branch" ]]; then
        bad "manifest says branch '$DEFENSE_BRANCH' but HEAD is '$branch'"
        info "the manifest is branch-specific; this usually means a bad merge"
        rc=1
    else
        ok "branch matches the manifest"
    fi
    if [[ -f "$REPO_ROOT/scratch/$SCRATCH_TARGET.cc" ]]; then
        ok "harness source: scratch/$SCRATCH_TARGET.cc"
    else
        bad "missing scratch/$SCRATCH_TARGET.cc"; rc=1
    fi
    if [[ -n "$DEFENSE_FLAGS" ]]; then
        ok "defense flags : $DEFENSE_FLAGS"
    else
        ok "defense flags : (none needed; the harness defaults reproduce the paper)"
    fi
    echo

    # --- the build ---
    echo "Build"
    if bin="$(find_binary)"; then
        ok "binary: ${bin#"$REPO_ROOT"/}"
        if check_binary_fresh "$bin"; then
            ok "binary is newer than all scratch sources"
            local out
            if out="$("$bin" --self-test 2>&1)" && printf '%s' "$out" | tail -3 | grep -q "ALL PASS"; then
                ok "--self-test reports ALL PASS"
            else
                bad "--self-test did not report ALL PASS"
                printf '%s\n' "$out" | tail -5 | sed 's/^/         /'
                rc=1
            fi
        else
            rc=1
        fi
    else
        bad "no built harness found in build/scratch/"
        info "run: ./tools/olsr-research.sh build"
        rc=1
    fi

    rule
    if [[ $rc -eq 0 ]]; then
        echo "  All checks passed. Try:  ./tools/olsr-research.sh smoke"
    else
        echo "  Some checks failed -- see above."
    fi
    rule
    return $rc
}

# =============================================================================
# build
# =============================================================================
# The reconfigure is NOT optional. The set of files in scratch/ differs between
# the two defense branches, and cmake does not discover a target that did not
# exist when it last configured. Skipping this step after a branch switch
# produces "no such target" at best and a stale binary at worst.
cmd_build() {
    load_manifest
    require_defense
    local jobs="${1:-$(nproc 2>/dev/null || echo 4)}"

    rule
    echo "  Building $DEFENSE_NAME"
    info "branch : $(current_branch)"
    info "target : scratch_$SCRATCH_TARGET"
    info "jobs   : $jobs"
    rule

    prune_dangling_stubs

    say "configuring (required after every branch switch)"
    ( cd "$REPO_ROOT" && ./ns3 configure --enable-examples ) \
        || die "./ns3 configure failed"

    say "building scratch_$SCRATCH_TARGET"
    ( cd "$REPO_ROOT" && cmake --build cmake-cache --target "scratch_$SCRATCH_TARGET" -j "$jobs" ) \
        || die "build of scratch_$SCRATCH_TARGET failed"

    local bin
    bin="$(find_binary)" || die "build reported success but no binary matching '*$SCRATCH_TARGET*' is in build/scratch/"
    check_binary_fresh "$bin" || die "binary is stale immediately after building -- check the clock on this machine"

    say "self-testing the binary"
    local out
    out="$("$bin" --self-test 2>&1)"
    if printf '%s' "$out" | tail -3 | grep -q "ALL PASS"; then
        ok "--self-test: ALL PASS"
    else
        printf '%s\n' "$out" | tail -10 >&2
        die "--self-test did not report ALL PASS"
    fi

    rule
    echo "  Ready: ${bin#"$REPO_ROOT"/}"
    rule
}

# =============================================================================
# use
# =============================================================================
cmd_use() {
    local want="${1:-}"
    [[ -n "$want" ]] || die "usage: olsr-research.sh use <trust|fpnt|dcfm|watchdog>"
    local branch
    branch="$(defense_branch "$want")" || die "unknown defense '$want' (expected: trust, fpnt, dcfm, watchdog)"

    if [[ "$(current_branch)" == "$branch" ]]; then
        say "already on $branch"
    else
        tree_is_clean || {
            echo "ERROR: the working tree has local changes; refusing to switch branches." >&2
            echo "       Commit or stash them first:" >&2
            git -C "$REPO_ROOT" status --short >&2
            exit 1
        }
        say "switching to $branch"
        git -C "$REPO_ROOT" checkout "$branch" || die "git checkout $branch failed"
    fi

    # Re-read: the manifest we want is the one on the branch we just moved to.
    load_manifest
    cmd_build "${2:-}"
}

# =============================================================================
# run -- one batch
# =============================================================================
# DEFENSE_FLAGS from the manifest are always applied, and always first, so a
# caller-supplied --extra can still override them if that is ever wanted.
run_batch() {
    local target="$1" outdir="$2" seed="$3" jobs="$4" extra="$5" mixed="$6"
    local args=( -n "$target" -j "$jobs" --direct
                 --defense "$DEFENSE_ID"
                 --ns3-dir "$REPO_ROOT"
                 -o "$outdir"
                 --start-seed "$seed" )
    local all_extra="$DEFENSE_FLAGS${extra:+ $extra}"
    [[ -n "$all_extra" ]] && args+=( --extra "$all_extra" )
    [[ "$mixed" == "1" ]] && args+=( --random-window-order )

    bash "$RUNNER" "${args[@]}"
    local rc=$?

    # Provenance the harness does not write for itself: the exact flags, the
    # commit they were run at, and the branch. Without this a CSV cannot be
    # traced back to a configuration six months from now.
    if [[ -d "$outdir" ]]; then
        {
            printf 'defense_id=%s\n'    "$DEFENSE_ID"
            printf 'defense_flags=%s\n' "$all_extra"
            printf 'branch=%s\n'        "$(current_branch)"
            printf 'commit=%s\n'        "$(git -C "$REPO_ROOT" rev-parse HEAD)"
            printf 'start_seed=%s\n'    "$seed"
            printf 'window_order=%s\n'  "$( [[ "$mixed" == "1" ]] && echo randomized || echo canonical )"
            printf 'date=%s\n'          "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        } > "$outdir/defense_flags.txt"
    fi
    return $rc
}

cmd_run() {
    load_manifest
    require_defense
    local target=2000 jobs="" out="" seed="" extra="" mobile=0 mixed=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -n|--num-accepted) target="$2"; shift 2 ;;
            -j|--jobs)         jobs="$2";   shift 2 ;;
            -o|--output-dir)   out="$2";    shift 2 ;;
            --start-seed)      seed="$2";   shift 2 ;;
            --extra)           extra="$2";  shift 2 ;;
            --mobile)          mobile=1;    shift ;;
            --mixed)           mixed=1;     shift ;;
            *) die "run: unknown option '$1' (see: olsr-research.sh help)" ;;
        esac
    done
    jobs="${jobs:-$(nproc 2>/dev/null || echo 4)}"
    [[ $mobile -eq 1 ]] && extra="--bMobility=true${extra:+ $extra}"

    local name="${DEFENSE_ID}_$( [[ $mobile -eq 1 ]] && echo mobile || echo static )"
    [[ $mixed -eq 1 ]] && name="${name}_mixed"
    out="${out:-$DEFAULT_OUT_ROOT/$name}"

    if [[ -z "$seed" ]]; then
        if   [[ $mobile -eq 1 && $mixed -eq 1 ]]; then seed="$BATCH_SEED_MOBILE_MIXED"
        elif [[ $mobile -eq 1 ]];                 then seed="$BATCH_SEED_MOBILE"
        elif [[ $mixed  -eq 1 ]];                 then seed="$BATCH_SEED_STATIC_MIXED"
        else                                           seed="$BATCH_SEED_STATIC"
        fi
    fi

    rule
    echo "  $DEFENSE_NAME -- dataset batch '$name'"
    info "accepted runs target : $target"
    info "jobs                 : $jobs"
    info "output               : $out"
    info "start seed           : $seed"
    info "defense flags        : ${DEFENSE_FLAGS:-(harness defaults)}"
    info "extra harness args   : ${extra:-(none)}"
    rule
    run_batch "$target" "$out" "$seed" "$jobs" "$extra" "$mixed"
}

# =============================================================================
# smoke
# =============================================================================
cmd_smoke() {
    load_manifest
    require_defense
    local out="$DEFAULT_OUT_ROOT/smoke_$DEFENSE_ID"
    rule
    echo "  Smoke test -- $DEFENSE_NAME"
    info "5 accepted runs into $out"
    info "This proves the whole chain works: build -> simulate -> CSV."
    rule
    rm -rf "$out"
    run_batch 5 "$out" "${BATCH_SEED_STATIC}" 2 "" 0 || {
        echo; bad "smoke test failed -- see $out/logs/"; return 1; }

    echo
    rule
    echo "  Smoke test output"
    rule
    local f
    for f in runs.csv windows_features.csv windows_labels.csv defense_flags.txt; do
        if [[ -s "$out/$f" ]]; then
            ok "$f ($(( $(wc -l < "$out/$f") - 1 )) data rows)"
        else
            bad "$f is missing or empty"
        fi
    done
    if [[ -s "$out/windows_features.csv" ]]; then
        echo
        info "feature columns (expect the 17 LISTENER columns, see docs/SCHEMA.md):"
        head -1 "$out/windows_features.csv" | tr ',' '\n' | nl -ba | sed 's/^/         /'
    fi
    rule
}

# =============================================================================
# batch -- the canonical dataset batches
# =============================================================================
# This is the reproduction path for the datasets described in docs/DATASETS.md.
# It runs the current branch's defense only; run it once per branch. Seed
# ranges come from the manifest and are disjoint per batch by construction, so
# the four defenses' datasets stay independent.
cmd_batch() {
    load_manifest
    require_defense
    local target=2000 jobs="" out_root="$DEFAULT_OUT_ROOT" mixed=0 detach=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -n|--num-accepted) target="$2";   shift 2 ;;
            -j|--jobs)         jobs="$2";     shift 2 ;;
            -o|--output-dir)   out_root="$2"; shift 2 ;;
            --mixed)           mixed=1;       shift ;;
            --detach)          detach=1;      shift ;;
            *) die "batch: unknown option '$1' (see: olsr-research.sh help)" ;;
        esac
    done
    jobs="${jobs:-$(nproc 2>/dev/null || echo 4)}"

    if [[ $detach -eq 1 ]]; then
        mkdir -p "$out_root"
        local log="$out_root/batch-$DEFENSE_ID.log"
        if pgrep -f "olsr-research.sh batch" >/dev/null 2>&1; then
            die "a batch driver is already running: $(pgrep -af 'olsr-research.sh batch')"
        fi
        tree_is_clean || die "working tree is dirty; refusing to launch a detached batch"
        say "launching detached; following output in $log"
        local fwd=( batch -n "$target" -j "$jobs" -o "$out_root" )
        [[ $mixed -eq 1 ]] && fwd+=( --mixed )
        setsid nohup bash "$0" "${fwd[@]}" >>"$log" 2>&1 </dev/null &
        disown
        sleep 2
        pgrep -f "olsr-research.sh batch" >/dev/null 2>&1 \
            && { echo "launched. tail -f $log"; return 0; } \
            || die "the detached batch did not start; see $log"
    fi

    # name | mobility | seed
    local specs=(
        "${DEFENSE_ID}_static|0|$BATCH_SEED_STATIC"
        "${DEFENSE_ID}_mobile|1|$BATCH_SEED_MOBILE"
    )
    if [[ $mixed -eq 1 ]]; then
        specs=(
            "${DEFENSE_ID}_static_mixed|0|$BATCH_SEED_STATIC_MIXED"
            "${DEFENSE_ID}_mobile_mixed|1|$BATCH_SEED_MOBILE_MIXED"
        )
    fi

    local status="$out_root/STATUS_$(echo "$DEFENSE_ID" | tr '[:lower:]' '[:upper:]')"
    mkdir -p "$out_root"
    set_status() { printf '%s\n' "$*" > "$status"; say "STATUS: $*"; }

    rule
    say "canonical dataset batches -- $DEFENSE_NAME"
    info "jobs=$jobs  target=$target accepted per batch"
    info "window order: $( [[ $mixed -eq 1 ]] && echo randomized || echo canonical )"
    info "output root : $out_root"
    rule

    # Everything below is resumable: the runner keeps a seed ledger and appends,
    # so re-running this after an interruption picks up where it stopped.
    local rc_all=0 no=0 spec name mob seed t0 t1 rc acc
    for spec in "${specs[@]}"; do
        no=$(( no + 1 ))
        IFS='|' read -r name mob seed <<< "$spec"
        say "----------------------------------------------------------------"
        say "BATCH $no/${#specs[@]}: $name (mobility=$mob, seed from $seed)"
        set_status "batch $no/${#specs[@]} $name RUNNING"

        t0=$(date +%s)
        run_batch "$target" "$out_root/$name" "$seed" "$jobs" \
                  "$( [[ "$mob" == "1" ]] && echo '--bMobility=true' )" "$mixed"
        rc=$?
        t1=$(date +%s)

        acc=0
        [[ -s "$out_root/$name/.runstate/accepted" ]] && acc="$(cat "$out_root/$name/.runstate/accepted")"
        say "BATCH $no $name finished rc=$rc accepted=$acc elapsed=$(( t1 - t0 ))s"
        if [[ $rc -ne 0 ]]; then
            set_status "batch $no/${#specs[@]} $name FAILED rc=$rc accepted=$acc"
            rc_all=1
            break          # fail fast: a broken batch usually breaks the next one too
        fi
        set_status "batch $no/${#specs[@]} $name DONE accepted=$acc"
    done

    [[ $rc_all -eq 0 ]] && set_status "ALL $DEFENSE_ID BATCHES DONE" \
                        || set_status "$DEFENSE_ID STOPPED WITH ERRORS"

    rule
    for spec in "${specs[@]}"; do
        IFS='|' read -r name _ _ <<< "$spec"
        local a=0 f=0
        [[ -s "$out_root/$name/.runstate/accepted" ]] && a="$(cat "$out_root/$name/.runstate/accepted")"
        [[ -s "$out_root/$name/windows_features.csv" ]] && f=$(( $(wc -l < "$out_root/$name/windows_features.csv") - 1 ))
        say "  $name: accepted=$a  feature_rows=$f"
    done
    rule
    return $rc_all
}

# =============================================================================
# help
# =============================================================================
cmd_help() {
    cat <<'EOF'
olsr-research.sh -- one entry point for the OLSR defense research.

USAGE
    ./tools/olsr-research.sh <command> [options]

COMMANDS
    doctor
        Check bash, the toolchain, the branch, the manifest and the build,
        then run the harness self-test. Start here.

    use <trust|fpnt|dcfm|watchdog> [JOBS]
        Switch to that defense's branch and build it. Refuses if the working
        tree is dirty. Always reconfigures cmake, which is mandatory after a
        branch switch because the scratch file set differs per branch.

    build [JOBS]
        Reconfigure and rebuild the current branch's harness, then self-test.

    smoke
        5 accepted runs into datasets/smoke_<defense>/, a couple of minutes.
        Prints the feature-CSV header so you can see real output immediately.

    run [options]
        One dataset batch for the current branch's defense.
          -n N              accepted runs to collect      (default 2000)
          -j J              parallel workers              (default: nproc)
          -o DIR            output directory              (default datasets/<name>)
          --mobile          enable node mobility (--bMobility=true)
          --mixed           randomize the 4 measurement windows per run
          --start-seed S    override the manifest's seed range
          --extra "ARGS"    extra harness arguments

    batch [options]
        Reproduce the canonical batches for this branch: static + mobile.
          -n N, -j J, -o DIR   as above (output root, default datasets/)
          --mixed              the randomized-window-order pair instead
          --detach             run in the background via setsid/nohup

    help
        This message.

NOTES
    The defense flags for the current branch are applied automatically from
    tools/defense.manifest. For TRUST this matters: without them only one of
    the paper's detection rules is live and detection collapses to ~0.1%.
    See docs/RUNNING.md.

    Every batch is resumable. The runner keeps a seed ledger and appends, so
    re-running after an interruption continues where it stopped.

    Full documentation: docs/QUICKSTART.md, docs/RUNNING.md, docs/DATASETS.md
EOF
}

# =============================================================================
# dispatch
# =============================================================================
case "${1:-help}" in
    doctor) shift; cmd_doctor "$@" ;;
    use)    shift; cmd_use    "$@" ;;
    build)  shift; cmd_build  "$@" ;;
    smoke)  shift; cmd_smoke  "$@" ;;
    run)    shift; cmd_run    "$@" ;;
    batch)  shift; cmd_batch  "$@" ;;
    help|-h|--help) cmd_help ;;
    *) echo "Unknown command: $1" >&2; echo >&2; cmd_help >&2; exit 1 ;;
esac
