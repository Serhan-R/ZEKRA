## roi_circuit_check.py

# Verifies whether the EXISTING zekra circuit
# (zekra_java/zekra/zekra.java) accepts ROI-pruned inputs from
# roi_extractor.py -- i.e. whether circuit changes are actually needed for
# function-level ROI pruning, or the existing shadow-stack/adjacency-list/
# execution-path verification already tolerates it as-is.
#
# Pipeline (all in-process, driving the existing scripts exactly as their
# own CLI/--pruned flag would -- nothing belonging to those scripts is ever
# written to on disk):
#   1. roi_extractor.extract_roi(app_dir, ...)
#        -> writes adjlist_pruned / numified_adjlist_pruned /
#           translator_pruned / numified_path_pruned into <app_dir>
#   2. circuit_input_formatter.main(...) configured exactly as --pruned does
#        -> writes the "in_*" formatted circuit inputs into a NEW scratch
#           directory (never <app_dir>, so the app's original in_* files
#           from a full, non-ROI extraction are never touched)
#   3. compile_circuit's compile()/configure_main_component() against a
#      FRESH COPY of the zekra java sources (never the original, since
#      configure_main_component() patches the .java file in place)
#
# Circuit sizing parameters (--adjlist-len, --adjlist-levels, --path-len,
# --stack-depth, --label-bitwidth, --bucket-bitwidth, --address-bitwidth)
# are derived automatically from the pruned files via
# circuit_input_formatter.py's get_min_*() helpers, plus a replay of the
# pruned path's call/ret tokens to compute the max shadow-stack depth.
#
# Exit code 0 = circuit accepted the ROI-pruned witness ("Sample Run ...
# finished!" observed). Exit code 1 = rejected, or the pipeline didn't run
# to completion (see printed output for which stage failed).

import os, sys, getopt, shutil, secrets

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPT_DIR)
sys.path.insert(0, SCRIPT_DIR)

import roi_extractor
import circuit_input_formatter as cif
import compile_circuit as cc

SAMPLE_RUN_SUCCESS_MARKER = 'Sample Run: Sample_Run1 finished!'


# ─────────────────────────── small file helpers ─────────────────────────────

def _ensure_trailing_slash(path):
    return path if path.endswith('/') else path + '/'


def _count_nonempty_lines(path):
    with open(path) as f:
        return sum(1 for line in f if line.strip())


def _read_path_jumpkinds(numified_path_pruned_file):
    """Returns the ordered list of jumpkind tokens ('call'/'ret'/'jump') from
    a numified_path_pruned file, skipping its 'initial_node=.. final_node=..'
    header line. Parsed directly (not via circuit_input_formatter.read_path)
    because we only need the jumpkind column here, and read_path's
    `empty_move_dst` padding semantics are irrelevant to that."""
    with open(numified_path_pruned_file) as f:
        lines = [l.rstrip() for l in f if l.strip()]
    jumpkinds = []
    for line in lines[1:]:
        parts = line.split()
        if parts:
            jumpkinds.append(parts[0])
    return jumpkinds


# ─────────────────────── stage 2: circuit_input_formatter ───────────────────

def configure_formatter_for_pruned(adjlist_levels=None, label_bitwidth=None,
                                    bucket_bitwidth=None, addr_bitwidth=None,
                                    pad_adjlist=None, pad_path=None):
    """
    Sets circuit_input_formatter's module-level globals exactly as its own
    `--pruned` CLI flag would (attributes on the imported module object only
    -- never edits circuit_input_formatter.py on disk).

    pad_adjlist must be sizing['adjlist_size']: zekra.java uses that same
    value as its "no destination" sentinel for call/jump/ret hints. If
    PAD_ADJLIST is left unset, read_adjlist() falls back to the raw unpadded
    node count, the two sides go out of sync by one, and it surfaces as a
    confusing forceEqual() mismatch inside the circuit rather than a clean
    Python error. pad_path is passed for the same reason, though currently a
    no-op (compute_sizing() never pads path_size).
    """
    cif.USE_PRUNED = True
    cif.ADJLIST_FILENAME = 'adjlist_pruned'
    cif.NUMIFIED_ADJLIST_FILENAME = 'numified_adjlist_pruned'
    cif.NUMIFIED_PATH_FILENAME = 'numified_path_pruned'
    cif.TRANSLATOR_FILENAME = 'translator_pruned'
    # circuit_input_formatter.py's own --pruned flag deliberately never
    # substitutes RECORDED_PATH_FILENAME (it's a no-op for path/forward/bidir
    # modes, where the execution path itself isn't touched). Region mode IS
    # different -- prune_region() actually trims the transition list, so we
    # must point at the recorded_path_pruned file that region_prune.py's
    # write_recorded_path_pruned() now writes, or the full unpruned path gets
    # loaded into a circuit array sized for the pruned path and overflows it.
    cif.RECORDED_PATH_FILENAME = 'recorded_path_pruned'
    cif.PAD_ADJLIST = pad_adjlist
    cif.PAD_PATH = pad_path
    cif.ADJLIST_LEVELS = adjlist_levels
    cif.LABEL_BITWIDTH = label_bitwidth
    cif.BUCKET_BITWIDTH = bucket_bitwidth
    cif.ADDR_BITWIDTH = addr_bitwidth


def compute_sizing(app_dir):
    """
    Derive every circuit sizing parameter compile_circuit.py needs, directly
    from the *_pruned files roi_extractor.py wrote into app_dir. Reuses
    circuit_input_formatter.py's own (read-only) get_min_*() helpers for the
    bitwidth math, and replays the pruned path's call/ret tokens to find the
    actual maximum shadow-stack depth reached.
    """
    in_dir = _ensure_trailing_slash(app_dir)
    configure_formatter_for_pruned()  # only filenames + PAD_*=None needed here

    adjlist_levels  = cif.get_min_adjlist_levels(in_dir)
    label_bitwidth  = cif.get_min_label_bitwidth(in_dir)
    bucket_bitwidth = cif.get_min_bucket_bitwidth(in_dir)
    addr_bitwidth   = cif.get_min_addr_bitwidth(in_dir)

    numified_adjlist_path = os.path.join(app_dir, 'numified_adjlist_pruned')
    numified_path_path    = os.path.join(app_dir, 'numified_path_pruned')

    # numified_adjlist_pruned = 1 dummy line (label 0) + n_pruned real lines.
    # The circuit additionally needs room for the "empty"/sentinel label
    # (n_pruned+1), so capacity = n_pruned + 2 = (lines in file) + 1 — this
    # matches region_prune.write_numified_files()'s own printed
    # recommendation ("--adjlist-len >= n_pruned+2").
    adjlist_size = _count_nonempty_lines(numified_adjlist_path) + 1

    jumpkinds = _read_path_jumpkinds(numified_path_path)
    path_size = len(jumpkinds)

    depth, max_depth = 0, 0
    for jk in jumpkinds:
        if jk == 'call':
            depth += 1
            max_depth = max(max_depth, depth)
        elif jk == 'ret':
            depth = max(depth - 1, 0)
    stack_depth = max(1, max_depth)

    # get_min_label_bitwidth() only sees real label values in the pruned
    # files -- it doesn't know zekra.java uses ADJLIST_SIZE itself as the
    # "no destination"/"no return" sentinel in TRANSLATION_HINTS (same
    # LABEL_BITWIDTH-sized wires). Too narrow, and that sentinel silently
    # truncates mod 2^LABEL_BITWIDTH (UnsignedInteger.mapValue(), no
    # exception) and fails forceEqual() against the untruncated
    # in_numified_path value. Widen to cover adjlist_size too.
    label_bitwidth = max(label_bitwidth, adjlist_size.bit_length())

    return dict(adjlist_size=adjlist_size, adjlist_levels=adjlist_levels,
                path_size=path_size, stack_depth=stack_depth,
                label_bitwidth=label_bitwidth, bucket_bitwidth=bucket_bitwidth,
                addr_bitwidth=addr_bitwidth)


def _random_nonce():
    """A fresh, cryptographically random field element in [0, p) used as a
    Poseidon blinding factor (nonce_path/nonce_translator/nonce_adjlist) or
    verifier challenge (nonce_verifier). Random (vs. circuit_input_formatter's
    default of 0) is what makes the in_*_digest commitments hiding -- see
    circuit_input_formatter.py's hash_*() functions."""
    return secrets.randbelow(cif.p)


def format_pruned_inputs(app_dir, out_dir, sizing, nonce_verifier, nonce_path,
                          nonce_translator, nonce_adjlist):
    """Runs circuit_input_formatter.main() in-process, configured exactly as
    --pruned would be, writing the formatted in_* files into out_dir (a NEW
    scratch directory — never app_dir, so the app's original full-extraction
    in_* files are never touched).

    The four nonce_* arguments are never hardcoded here -- check() defaults
    each to a fresh _random_nonce() unless the caller (or --nonce-* on the
    CLI) pins a specific value. Hardcoding them to 0 (the old behavior) would
    make every in_*_digest a deterministic, unblinded hash of the real data."""
    configure_formatter_for_pruned(
        adjlist_levels=sizing['adjlist_levels'],
        label_bitwidth=sizing['label_bitwidth'],
        bucket_bitwidth=sizing['bucket_bitwidth'],
        addr_bitwidth=sizing['addr_bitwidth'],
        pad_adjlist=sizing['adjlist_size'],
        pad_path=sizing['path_size'])
    os.makedirs(out_dir, exist_ok=True)
    cif.main(_ensure_trailing_slash(app_dir), _ensure_trailing_slash(out_dir),
              nonce_verifier=nonce_verifier, nonce_path=nonce_path,
              nonce_translator=nonce_translator, nonce_adjlist=nonce_adjlist)


# ───────────────────────── stage 3: compile_circuit ──────────────────────────

def _copy_tree_overwrite(src, dst):
    """Like shutil.copytree(..., dirs_exist_ok=True), but never unlinks --
    only creates dirs and overwrites file contents in place via
    shutil.copyfile. See prepare_zekra_copy() for why."""
    os.makedirs(dst, exist_ok=True)
    for name in os.listdir(src):
        s = os.path.join(src, name)
        d = os.path.join(dst, name)
        if os.path.isdir(s):
            _copy_tree_overwrite(s, d)
        else:
            shutil.copyfile(s, d)


def prepare_zekra_copy(zekra_dir, work_dir):
    """
    compile_circuit.configure_main_component() patches zekra.java IN PLACE,
    so we copy the zekra java sources into a scratch dir under work_dir and
    point compile_circuit at the copy -- the original zekra_dir is never
    touched.

    Uses _copy_tree_overwrite() rather than rmtree()+copytree(): some
    sandboxed/FUSE-backed mounts reject unlink() on files in this scratch
    dir with PermissionError even when permissions are fully open, but
    overwriting file contents in place works fine.
    """
    dest = os.path.join(work_dir, 'zekra_roi_check_copy')
    _copy_tree_overwrite(zekra_dir, dest)
    return dest


def compile_pruned_circuit(formatted_input_dir, output_dir, sizing, zekra_copy_dir):
    """Runs compile_circuit's configure_main_component()+compile() in-process
    (mirrors compile_circuit.main(), so we can inspect stdout for the success
    marker that main() only prints). Must run with CWD == repo root, since
    compile_circuit.compile() shells out to javac/java with a relative
    classpath entry ('xjsnark_backend.jar')."""
    cc.ZEKRA_DIR = zekra_copy_dir
    cc.ZEKRA_COMPONENT_NAME = 'zekra'
    cc.COMPUTE_WORKLOAD_DISTRIBUTION = False
    cc.ADJLIST_SIZE = sizing['adjlist_size']
    cc.ADJLIST_LEVELS = sizing['adjlist_levels']
    cc.EXECUTION_PATH_SIZE = sizing['path_size']
    cc.SHADOWSTACK_DEPTH = sizing['stack_depth']
    cc.LABEL_BITWIDTH = sizing['label_bitwidth']
    cc.BUCKET_BITWIDTH = sizing['bucket_bitwidth']
    cc.ADDR_BITWIDTH = sizing['addr_bitwidth']

    os.makedirs(output_dir, exist_ok=True)
    prev_cwd = os.getcwd()
    try:
        os.chdir(REPO_ROOT)  # xjsnark_backend.jar must be in CWD
        cc.configure_main_component(formatted_input_dir, output_dir)
        stdout, stderr = cc.compile(cc.ZEKRA_DIR, cc.ZEKRA_COMPONENT_NAME)
    finally:
        os.chdir(prev_cwd)

    total_constraints = cc.get_constraints(stdout)
    print('Total constraints: %s' % total_constraints)
    print('Arithmetic circuit stored in: %s' % os.path.join(output_dir, 'zekra.arith'))
    print('Formatted inputs stored in: %s'
          % os.path.join(output_dir, 'zekra_Sample_Run1.in'))
    return stdout, stderr


# ─────────────────────────────── orchestration ───────────────────────────────

def check(app_dir, zekra_dir=None, work_dir=None, top_n=1, model=None, provider=None,
          heuristic_only=False, func_names=None, force_redetect=False,
          nonce_verifier=None, nonce_path=None, nonce_translator=None, nonce_adjlist=None):
    app_dir = os.path.abspath(app_dir)
    zekra_dir = os.path.abspath(zekra_dir or os.path.join(REPO_ROOT, 'zekra_java', 'zekra'))
    work_dir = os.path.abspath(work_dir or os.path.join(app_dir, '_roi_circuit_check'))
    formatted_dir = os.path.join(work_dir, 'formatted_inputs')
    circuit_out_dir = os.path.join(work_dir, 'circuit_output')
    os.makedirs(work_dir, exist_ok=True)

    # Default every unset nonce to a fresh random field element rather than 0
    # -- a fixed/predictable blinding factor defeats the whole point of the
    # in_*_digest commitments being hiding (see _random_nonce()). Pass
    # --nonce-* on the CLI (or a non-None value programmatically) to pin a
    # specific value, e.g. to reproduce a previous run.
    if nonce_verifier is None:   nonce_verifier   = _random_nonce()
    if nonce_path is None:       nonce_path       = _random_nonce()
    if nonce_translator is None: nonce_translator = _random_nonce()
    if nonce_adjlist is None:    nonce_adjlist    = _random_nonce()

    print('=' * 70)
    print('[1/4] Detecting + pruning ROI for %s' % app_dir)
    names = roi_extractor.extract_roi(app_dir, top_n=top_n, model=model, provider=provider,
                                       force_heuristic=heuristic_only,
                                       func_names=func_names, force_redetect=force_redetect)
    if not names:
        print('[roi_circuit_check] FAIL -- could not establish a ROI; aborting.')
        return False

    print('\n[2/4] Computing circuit sizing parameters from pruned files')
    sizing = compute_sizing(app_dir)
    for k, v in sizing.items():
        print('  %-16s = %s' % (k, v))

    print('\n[3/4] Formatting pruned circuit inputs -> %s' % formatted_dir)
    print('  nonce_verifier   = %s' % nonce_verifier)
    print('  nonce_path       = %s' % nonce_path)
    print('  nonce_translator = %s' % nonce_translator)
    print('  nonce_adjlist    = %s' % nonce_adjlist)
    format_pruned_inputs(app_dir, formatted_dir, sizing,
                          nonce_verifier, nonce_path, nonce_translator, nonce_adjlist)

    print('\n[4/4] Copying zekra sources (never the originals) + compiling circuit')
    zekra_copy_dir = prepare_zekra_copy(zekra_dir, work_dir)
    stdout, stderr = compile_pruned_circuit(formatted_dir, circuit_out_dir, sizing,
                                             zekra_copy_dir)

    success = SAMPLE_RUN_SUCCESS_MARKER in stdout
    print('=' * 70)
    if success:
        print('[roi_circuit_check] PASS -- the EXISTING zekra circuit (%s) accepted the '
              'ROI-pruned witness for %s (ROI function(s): %s).'
              % (zekra_dir, app_dir, ','.join(names)))
        print('No circuit modifications appear necessary for function-level ROI pruning.')
    else:
        print('[roi_circuit_check] FAIL -- the existing zekra circuit REJECTED the '
              'ROI-pruned witness for %s (ROI function(s): %s).' % (app_dir, ','.join(names)))
        print('Circuit changes (e.g. shadow-stack handling at ROI segment boundaries) are '
              'likely required. Full stdout/stderr below:\n')
        print(stdout)
        print(stderr)
    return success


def usage():
    print('Usage: %s -a <app_dir> [options]' % sys.argv[0])
    print('  -a <path>            Application directory (extractor.py output + a')
    print('                       compiled "main" binary)')
    print('  --zekra-dir <dir>    Existing ZEKRA java sources to validate against')
    print('                       (default: zekra_java/zekra under the repo root).')
    print('                       This directory is only ever READ from -- it is')
    print('                       copied to a scratch dir before any patching.')
    print('  --work-dir <dir>     Scratch directory for formatted inputs + compiled')
    print('                       circuit artifacts (default: <app_dir>/_roi_circuit_check)')
    print('  --top-n <num>        Number of ROI functions for auto-detection (default: 3)')
    print('  --provider <name>    LLM provider for auto-detection: "anthropic" or "gemini"')
    print('                       (default: ROI_DETECTOR_PROVIDER env var, else "anthropic")')
    print('  --model <name>       Model id for LLM-based ROI detection (meaning depends')
    print('                       on --provider -- see roi_detector.py --help)')
    print('  --heuristic-only     Skip the LLM call, use the static heuristic directly')
    print('  --function <names>   Comma-separated function names -- manual ROI override,')
    print('                       skips roi_detector.py entirely')
    print('  --force-redetect     Ignore any cached ROI selection for this app_dir and')
    print('                       query the detector fresh (see roi_detector.py)')
    print('  --nonce-verifier <n> Verifier nonce baked into the execution-path digest')
    print('                       (default: a fresh random field element per run)')
    print('  --nonce-path <n>     Blinding factor for the execution-path digest')
    print('                       (default: a fresh random field element per run)')
    print('  --nonce-translator <n> Blinding factor for the translator digest')
    print('                       (default: a fresh random field element per run)')
    print('  --nonce-adjlist <n>  Blinding factor for the adjacency-list digest')
    print('                       (default: a fresh random field element per run)')


if __name__ == '__main__':
    app_dir = None
    zekra_dir = None
    work_dir = None
    top_n = 3
    model = None
    provider = None
    heuristic_only = False
    func_names = None
    force_redetect = False
    nonce_verifier = None
    nonce_path = None
    nonce_translator = None
    nonce_adjlist = None
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'ha:',
                                    ['zekra-dir=', 'work-dir=', 'top-n=', 'model=',
                                     'provider=', 'heuristic-only', 'function=',
                                     'force-redetect', 'nonce-verifier=', 'nonce-path=',
                                     'nonce-translator=', 'nonce-adjlist='])
    except getopt.GetoptError as err:
        print(err); usage(); sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            usage(); sys.exit()
        elif opt == '-a':
            app_dir = arg
        elif opt == '--zekra-dir':
            zekra_dir = arg
        elif opt == '--work-dir':
            work_dir = arg
        elif opt == '--top-n':
            top_n = int(arg)
        elif opt == '--model':
            model = arg
        elif opt == '--provider':
            provider = arg
        elif opt == '--heuristic-only':
            heuristic_only = True
        elif opt == '--function':
            func_names = [n.strip() for n in arg.split(',') if n.strip()]
        elif opt == '--force-redetect':
            force_redetect = True
        elif opt == '--nonce-verifier':
            nonce_verifier = int(arg)
        elif opt == '--nonce-path':
            nonce_path = int(arg)
        elif opt == '--nonce-translator':
            nonce_translator = int(arg)
        elif opt == '--nonce-adjlist':
            nonce_adjlist = int(arg)
    if not app_dir:
        usage(); sys.exit(2)

    for _label, _val in [('--nonce-verifier', nonce_verifier), ('--nonce-path', nonce_path),
                          ('--nonce-translator', nonce_translator),
                          ('--nonce-adjlist', nonce_adjlist)]:
        if _val is not None and len(format(_val, '0b')) >= cif.P_BITWIDTH:
            print('%s: %s value %s is too big for the field (max bitwidth %s)'
                  % (sys.argv[0], _label, _val, cif.P_BITWIDTH))
            usage(); sys.exit(2)

    ok = check(app_dir, zekra_dir=zekra_dir, work_dir=work_dir, top_n=top_n, model=model,
               provider=provider, heuristic_only=heuristic_only, func_names=func_names,
               force_redetect=force_redetect, nonce_verifier=nonce_verifier,
               nonce_path=nonce_path, nonce_translator=nonce_translator,
               nonce_adjlist=nonce_adjlist)
    sys.exit(0 if ok else 1)
