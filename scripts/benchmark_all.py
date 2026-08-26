#!/usr/bin/python3
#################################
## benchmark_all.py
#################################
# Runs the full ZEKRA pipeline (ROI detect -> region_bidir prune -> circuit
# compile -> keygen -> setup_serializer -> prove -> verify) for every app
# under embench-iot-applications/, and records per-app metrics to a CSV:
# constraint count, wall time + peak RSS for each of the four crypto stages,
# constraint-satisfaction / verification result, and overall pass/fail.
#
# ROI detection + circuit compile (roi_circuit_check.check()) runs in-process
# via direct imports, same as roi_circuit_check.py's own __main__ does. Only
# the four crypto binaries are subprocesses, each wrapped with
# `/usr/bin/time -v` to get wall time + max RSS uniformly (falls back to
# wall-time-only if /usr/bin/time isn't installed).
#
# Resumable: apps already present in --out are skipped on a re-run unless
# --force is given, and results are written to disk after every app -- a
# full sweep doesn't need to finish in one sitting.
#
# Every app is fully re-extracted from its raw .c sources before anything
# else runs: extractor.run() recompiles "main" and rebuilds the CFG +
# adjlist/recorded_path/translator/numified_* from scratch (same as
# run_pipeline.sh's stage [1/6]). This is deliberately NOT skipped/cached --
# leftover extraction files from an older extractor.py run (or a stale
# mount/checkout) can silently desync from the current binary, so every
# sweep starts from a clean, guaranteed-fresh extraction. Pass --skip-extract
# to reuse whatever's already in the app directory instead (faster, but only
# safe if you're sure those files are current).
#
# Usage:
#   python3 scripts/benchmark_all.py [options]
#   python3 scripts/benchmark_all.py --apps minver,crc32
#   python3 scripts/benchmark_all.py --max-apps 5      # chunk a long sweep
#   python3 scripts/benchmark_all.py --force --apps minver

import os, sys, csv, json, re, time, getopt, subprocess, shutil, io, contextlib

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPT_DIR)
sys.path.insert(0, SCRIPT_DIR)

import extractor               # run() -- full re-extraction (compile main + CFG + path)
                               # SpillingCFG patch is applied inside extractor.py on import
import roi_circuit_check as rcc

APPS_DIR = os.path.join(REPO_ROOT, 'embench-iot-applications')
BIN_DIR = os.path.join(REPO_ROOT, 'jsnark', 'libsnark', 'build', 'libsnark', 'jsnark_interface')
TIME_BIN = '/usr/bin/time' if os.path.exists('/usr/bin/time') else shutil.which('time')

REQUIRED_EXTRACTION_FILES = ('adjlist', 'recorded_path', 'translator', 'main')
CRYPTO_TOOLS = ('run_keygen_raw', 'run_setup_serializer', 'run_prover_raw', 'run_verifier_only')

RESULTS_FIELDS = [
    'app', 'status', 'error', 'roi_functions', 'roi_method',
    'constraints', 'primary_inputs', 'auxiliary_inputs',
    'keygen_time_s', 'keygen_rss_mb',
    'setup_time_s', 'setup_rss_mb',
    'prover_time_s', 'prover_rss_mb', 'constraints_satisfied',
    'verifier_time_s', 'verifier_rss_mb', 'verified',
    'log_file',
]

# Minimum seconds between consecutive Gemini API calls when --use-llm is active.
# Free-tier Gemini flash is ~2 RPM = 30 s minimum gap; 35 s adds a small safety
# margin. If an app's own runtime already exceeds this interval the sleep is
# skipped. Has no effect when --func-name is set (no API call is made).
GEMINI_MIN_INTERVAL_S = 35.0


def has_prior_extraction(app_dir):
    return all(os.path.isfile(os.path.join(app_dir, f)) for f in REQUIRED_EXTRACTION_FILES)


def run_extraction(app_dir):
    """Always re-extracts from raw .c sources: extractor.run() recompiles
    "main" and rebuilds the CFG + adjlist/recorded_path/translator/numified_*
    from scratch -- see module docstring for why this isn't skipped/cached.
    Returns (ok, error_or_None, captured_output_for_log)."""
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            output = extractor.run(app_dir)
    except Exception as e:
        return False, 'extractor.run() raised: %r' % e, buf.getvalue()
    log = buf.getvalue() + '\n' + output
    if 'ERROR' in output:
        # output's last non-empty line is the specific "ERROR: ..." reason.
        reason = next((l for l in reversed(output.splitlines()) if l.strip()), output)
        return False, 'extraction failed: %s' % reason.strip(), log
    if not has_prior_extraction(app_dir):
        return False, 'extractor.run() reported success but expected output files are missing', log
    return True, None, log


def run_timed(cmd, cwd=None):
    """Runs cmd, optionally under `/usr/bin/time -v`. Returns
    (rc, stdout, stderr, wall_seconds, max_rss_mb_or_None)."""
    full_cmd = [TIME_BIN, '-v'] + cmd if TIME_BIN else cmd
    t0 = time.time()
    proc = subprocess.run(full_cmd, cwd=cwd, capture_output=True, text=True)
    wall = time.time() - t0
    rss_mb = None
    if TIME_BIN:
        m = re.search(r'Maximum resident set size \(kbytes\):\s*(\d+)', proc.stderr)
        if m:
            rss_mb = int(m.group(1)) / 1024.0
    return proc.returncode, proc.stdout, proc.stderr, wall, rss_mb


def parse_int(pattern, text):
    m = re.search(pattern, text)
    return int(m.group(1)) if m else None


def clean_artifacts(out_dir):
    """Best-effort; the crypto tools open(.., 'wb') and overwrite regardless,
    so a failed unlink here (some sandboxed mounts reject it) isn't fatal."""
    for f in ('proving_key_raw.bin', 'proving_key.bin', 'verification_key.bin',
              'circuit_metadata.bin', 'constraint_system.bin', 'proof.bin',
              'primary_input.bin'):
        try:
            os.remove(os.path.join(out_dir, f))
        except OSError:
            pass


CHECK_FAIL_MARKERS = [
    # Order matters: 'could not establish a ROI' is a generic wrapper message
    # that's also present whenever either specific case below fires, so the
    # specific markers must be checked first or they'd never be reached.
    ('never visited by the recorded execution path',
     'ROI function(s) never visited by the recorded path (likely inlined/split under -Os)'),
    ('REJECTED the', 'existing circuit rejected the ROI-pruned witness'),
    ('could not establish a ROI', 'no usable ROI (LLM/heuristic detection failed)'),
]


def run_app(app_name, heuristic_only=True, top_n=1, log_path=None, skip_extract=False,
            func_names=None, prune_mode='region_bidir'):
    app_dir = os.path.join(APPS_DIR, app_name)
    row = {f: '' for f in RESULTS_FIELDS}
    row['app'] = app_name
    log_chunks = []

    if skip_extract:
        if not has_prior_extraction(app_dir):
            row['status'] = 'SKIPPED'
            row['error'] = 'missing adjlist/recorded_path/translator/main (never extracted) and --skip-extract given'
            return row
    else:
        ok, err, extract_log = run_extraction(app_dir)
        log_chunks.append('=== extractor.run() ===\n' + extract_log)
        if not ok:
            row['status'] = 'FAIL'
            row['error'] = err
            if log_path:
                _write_log(log_path, log_chunks)
            return row

    # --- ROI detect + region_bidir prune + circuit compile (in-process) ----
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            ok = rcc.check(app_dir, top_n=top_n, heuristic_only=heuristic_only,
                           force_redetect=True, func_names=func_names,
                           prune_mode=prune_mode)
    except Exception as e:
        row['status'] = 'FAIL'
        row['error'] = 'roi_circuit_check raised: %r' % e
        log_chunks.append(buf.getvalue())
        if log_path:
            _write_log(log_path, log_chunks)
        return row
    check_output = buf.getvalue()
    log_chunks.append(check_output)

    cache_path = os.path.join(app_dir, '.roi_detect_cache.json')
    if os.path.isfile(cache_path):
        try:
            with open(cache_path) as f:
                cached = json.load(f)
            row['roi_functions'] = ','.join(cached.get('names') or [])
            row['roi_method'] = cached.get('method') or ''
        except (OSError, json.JSONDecodeError):
            pass

    if not ok:
        row['status'] = 'FAIL'
        row['error'] = next((msg for marker, msg in CHECK_FAIL_MARKERS if marker in check_output),
                             'roi_circuit_check.check() returned False (see log)')
        if log_path:
            _write_log(log_path, log_chunks)
        return row

    out_dir = os.path.join(app_dir, '_roi_circuit_check', 'circuit_output')
    arith = os.path.join(out_dir, 'zekra.arith')
    witnesses = [f for f in os.listdir(out_dir) if f.endswith('.in')] if os.path.isdir(out_dir) else []
    if not os.path.isfile(arith) or not witnesses:
        row['status'] = 'FAIL'
        row['error'] = 'zekra.arith or witness .in file missing after compile'
        if log_path:
            _write_log(log_path, log_chunks)
        return row
    witness = os.path.join(out_dir, witnesses[0])

    clean_artifacts(out_dir)

    # --- keygen --------------------------------------------------------------
    rc, out, errtxt, wall, rss = run_timed(
        [os.path.join(BIN_DIR, 'run_keygen_raw'), 'gg', arith, out_dir + '/', '--no-standard'])
    log_chunks.append('\n=== run_keygen_raw ===\n%s\n%s' % (out, errtxt))
    row['keygen_time_s'] = round(wall, 3)
    row['keygen_rss_mb'] = round(rss, 1) if rss else ''
    row['constraints'] = parse_int(r'Constraints:\s*(\d+)', out) or ''
    row['primary_inputs'] = parse_int(r'Primary inputs:\s*(\d+)', out) or ''
    row['auxiliary_inputs'] = parse_int(r'Auxiliary inputs:\s*(\d+)', out) or ''
    if rc != 0:
        row['status'] = 'FAIL'
        row['error'] = 'run_keygen_raw exited %d' % rc
        if log_path:
            _write_log(log_path, log_chunks)
        return row

    # --- setup_serializer ------------------------------------------------------
    pk_raw = os.path.join(out_dir, 'proving_key_raw.bin')
    rc, out, errtxt, wall, rss = run_timed(
        [os.path.join(BIN_DIR, 'run_setup_serializer'), arith, out_dir + '/'])
    log_chunks.append('\n=== run_setup_serializer ===\n%s\n%s' % (out, errtxt))
    row['setup_time_s'] = round(wall, 3)
    row['setup_rss_mb'] = round(rss, 1) if rss else ''
    if rc != 0:
        row['status'] = 'FAIL'
        row['error'] = 'run_setup_serializer exited %d' % rc
        if log_path:
            _write_log(log_path, log_chunks)
        return row

    # --- prove -----------------------------------------------------------------
    metadata = os.path.join(out_dir, 'circuit_metadata.bin')
    rc, out, errtxt, wall, rss = run_timed(
        [os.path.join(BIN_DIR, 'run_prover_raw'), arith, pk_raw, metadata, witness, out_dir + '/'])
    log_chunks.append('\n=== run_prover_raw ===\n%s\n%s' % (out, errtxt))
    row['prover_time_s'] = round(wall, 3)
    row['prover_rss_mb'] = round(rss, 1) if rss else ''
    row['constraints_satisfied'] = 'YES' if 'Constraints satisfied: YES' in out else 'NO'
    if rc != 0:
        row['status'] = 'FAIL'
        row['error'] = ('run_prover_raw exited %d (constraints_satisfied=%s)'
                         % (rc, row['constraints_satisfied']))
        if log_path:
            _write_log(log_path, log_chunks)
        return row

    # --- verify ------------------------------------------------------------------
    vk = os.path.join(out_dir, 'verification_key.bin')
    primary_input = os.path.join(out_dir, 'primary_input.bin')
    proof = os.path.join(out_dir, 'proof.bin')
    rc, out, errtxt, wall, rss = run_timed(
        [os.path.join(BIN_DIR, 'run_verifier_only'), 'gg', vk, primary_input, proof])
    log_chunks.append('\n=== run_verifier_only ===\n%s\n%s' % (out, errtxt))
    row['verifier_time_s'] = round(wall, 3)
    row['verifier_rss_mb'] = round(rss, 1) if rss else ''
    row['verified'] = 'ACCEPTED' if rc == 0 else 'REJECTED'
    row['status'] = 'PASS' if rc == 0 else 'FAIL'
    if rc != 0:
        row['error'] = 'verifier REJECTED the proof'

    if log_path:
        _write_log(log_path, log_chunks)
    return row


def _write_log(log_path, chunks):
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    with open(log_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(chunks))


def load_existing(csv_path):
    rows = []
    if os.path.isfile(csv_path):
        with open(csv_path, newline='', encoding='utf-8-sig') as f:
            rows = list(csv.DictReader(f))
    return rows


def write_results(csv_path, rows):
    with open(csv_path, 'w', newline='', encoding='utf-8-sig') as f:
        w = csv.DictWriter(f, fieldnames=RESULTS_FIELDS)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, '') for k in RESULTS_FIELDS})


def usage():
    print('Usage: %s [options]' % sys.argv[0])
    print('  --apps <names>     Comma-separated app names (default: every subdir of')
    print('                     embench-iot-applications/)')
    print('  --out <path>       Results CSV (default: <repo_root>/benchmark_results.csv)')
    print('  --force            Re-run apps even if already present in --out')
    print('  --use-llm          Use LLM ROI auto-detection instead of the heuristic')
    print('                     (slower, needs ANTHROPIC_API_KEY/GEMINI_API_KEY)')
    print('  --top-n <num>      ROI functions to select per app (default: 1)')
    print('  --max-apps <num>   Stop after this many NEW apps -- resume later with the')
    print('                     same command (results already written are kept)')
    print('  --skip-extract     Reuse existing adjlist/recorded_path/translator/main')
    print('                     instead of re-running extractor.py (faster, but only')
    print('                     safe if those files are known to be current)')
    print('  --func-name <n>    Pin the ROI to this exact function name, bypassing the')
    print('                     heuristic/LLM detector entirely. Use "benchmark_body"')
    print('                     for a clean sweep of embench-iot apps.')
    print('  --prune-mode <m>   Pruning strategy: region_bidir (default) or region_trace')
    print('  --list             Print discovered app names and exit, run nothing')


def main(argv):
    out_path = os.path.join(REPO_ROOT, 'benchmark_results.csv')
    apps_arg = None
    force = False
    heuristic_only = True
    top_n = 1
    prune_mode = 'region_bidir'
    max_apps = None
    list_only = False
    skip_extract = False
    func_names = None
    try:
        opts, _ = getopt.getopt(argv, 'h', ['apps=', 'out=', 'force', 'use-llm', 'top-n=',
                                             'max-apps=', 'skip-extract', 'func-name=',
                                             'prune-mode=', 'list', 'help'])
    except getopt.GetoptError as err:
        print(err); usage(); sys.exit(2)
    for opt, arg in opts:
        if opt in ('-h', '--help'):
            usage(); sys.exit()
        elif opt == '--apps':
            apps_arg = arg
        elif opt == '--out':
            out_path = arg
        elif opt == '--force':
            force = True
        elif opt == '--use-llm':
            heuristic_only = False
        elif opt == '--top-n':
            top_n = int(arg)
        elif opt == '--max-apps':
            max_apps = int(arg)
        elif opt == '--skip-extract':
            skip_extract = True
        elif opt == '--func-name':
            func_names = [arg.strip()]
        elif opt == '--prune-mode':
            prune_mode = arg
        elif opt == '--list':
            list_only = True

    if apps_arg:
        app_names = [a.strip() for a in apps_arg.split(',') if a.strip()]
    else:
        app_names = sorted(d for d in os.listdir(APPS_DIR)
                            if os.path.isdir(os.path.join(APPS_DIR, d)))

    if list_only:
        print('\n'.join(app_names))
        return

    rows = [] if force else load_existing(out_path)
    done = set() if force else {r['app'] for r in rows}
    logs_dir = os.path.join(os.path.dirname(os.path.abspath(out_path)), 'benchmark_logs')

    # Tracks when the last Gemini API call was fired so we can enforce
    # GEMINI_MIN_INTERVAL_S between consecutive calls (free-tier RPM guard).
    last_llm_call_t = 0.0

    processed = 0
    for app_name in app_names:
        if app_name in done:
            print('[benchmark_all] %-16s SKIP (already in %s)' % (app_name, out_path))
            continue
        if max_apps is not None and processed >= max_apps:
            print('[benchmark_all] reached --max-apps %d -- stopping, rerun the same '
                  'command to continue' % max_apps)
            break

        # -- Gemini RPM throttle -----------------------------------------------
        # Only applies when --use-llm is active and no --func-name pin is set
        # (pinned names bypass the LLM entirely, so no API call is made).
        if not heuristic_only and func_names is None:
            elapsed_since_llm = time.time() - last_llm_call_t
            wait = GEMINI_MIN_INTERVAL_S - elapsed_since_llm
            if wait > 0:
                print('[benchmark_all] Gemini throttle: waiting %.1fs to stay under '
                      'free-tier RPM limit (%.0fs since last call)...'
                      % (wait, elapsed_since_llm))
                time.sleep(wait)
            last_llm_call_t = time.time()
        # ----------------------------------------------------------------------

        print('=' * 70)
        print('[benchmark_all] %s' % app_name)
        print('=' * 70)
        t0 = time.time()
        log_path = os.path.join(logs_dir, '%s.log' % app_name)
        try:
            row = run_app(app_name, heuristic_only=heuristic_only, top_n=top_n, log_path=log_path,
                          skip_extract=skip_extract, func_names=func_names,
                          prune_mode=prune_mode)
        except Exception as e:
            row = {f: '' for f in RESULTS_FIELDS}
            row['app'] = app_name
            row['status'] = 'ERROR'
            row['error'] = 'unhandled exception: %r' % e
        elapsed = time.time() - t0
        print('[benchmark_all] %-16s %-8s (%.1fs) %s' %
              (app_name, row['status'], elapsed, row.get('error', '')))
        rows.append(row)
        processed += 1
        write_results(out_path, rows)  # after every app -- crash/resume safe

    print()
    print('Results: %s' % out_path)
    print('Per-app logs: %s' % logs_dir)
    counts = {}
    for r in rows:
        counts[r['status']] = counts.get(r['status'], 0) + 1
    print(' / '.join('%d %s' % (v, k) for k, v in sorted(counts.items())) +
          ' (of %d total)' % len(rows))


if __name__ == '__main__':
    main(sys.argv[1:])
