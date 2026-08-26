#!/usr/bin/python3
#################################
## roi_extractor.py
#################################
# The "ROI input formatter/extractor" -- instead of extracting the entire
# CFG + a sample execution path (as extractor.py does), narrows the
# already-extracted CFG/path down to a "region of interest" (ROI):
#
#   1. roi_detector.detect_roi() picks ROI function name(s) for the app
#      (LLM-based, with a static heuristic fallback -- see roi_detector.py).
#   2. region_prune.prune_dir(app_dir, mode='region', func_names=...) builds
#      the ROI subgraph (plus the virtual-entry/virtual-exit-wrapped path)
#      and writes the standard "*_pruned" files that circuit_input_formatter.py
#      already reads via its --pruned flag.
##
# Prerequisite: extractor.py must already have been run for <app_dir>
# (adjlist/recorded_path/translator + a compiled <app_dir>/main exist) --
# function-level ROI selection needs `nm` to resolve function addresses,
# which needs the binary. If recompiling by hand, match extractor.py's
# flags: gcc -Os -g0 -lm -fno-optimize-sibling-calls -o main *.c

import os, sys, getopt

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import region_prune
import roi_detector


def extract_roi(app_dir, top_n=1, model=None, force_heuristic=False, func_names=None,
                 provider=None, force_redetect=False, mode='region_bidir'):
    """
    If func_names is given, detection is skipped and those names are used
    directly (still validated against the binary's symbol table via `nm`).
    Otherwise roi_detector.detect_roi() chooses the ROI automatically
    (LLM-based with heuristic fallback, cached per app_dir -- see
    roi_detector.py; force_redetect bypasses that cache).

    mode selects the region_prune.py pruning strategy applied once the ROI
    function(s) are known: 'region_bidir' (default) keeps the ROI plus
    everything reachable between it and the program's real start/end nodes,
    producing a richer CFG with many valid paths. 'region' is the older,
    stricter strategy that keeps ONLY the ROI's own nodes, bridged by
    synthetic virtual_entry/virtual_exit nodes -- still available for
    callers that want the smaller, ROI-only circuit.

    Returns the function names used to build the ROI, or [] if none could
    be established -- including when the chosen function(s) are valid
    symbols but never visited by the recorded execution path (e.g. inlined
    away under -Os) -- in which case no "_pruned" files are written.
    """
    if func_names:
        names, method = list(func_names), 'manual'
    else:
        names, method = roi_detector.detect_roi(
            app_dir, top_n=top_n, model=model, force_heuristic=force_heuristic,
            provider=provider, force_redetect=force_redetect)

    if not names:
        print('[roi_extractor] No ROI function could be determined for %s -- aborting.'
              % app_dir)
        return []

    print('[roi_extractor] ROI function(s) for %s (%s): %s'
          % (app_dir, method, ','.join(names)))

    # region_prune.prune_dir's region/region_bidir modes pass app_dir through
    # to lookup_function_ranges() itself, which calibrates the PIE rebase
    # delta -- no need to pre-resolve ranges here first.
    new_path_info = region_prune.prune_dir(app_dir, mode=mode, func_names=names)
    if new_path_info is None:
        print('[roi_extractor] Region pruning failed for %s -- aborting.' % app_dir)
        return []
    if not new_path_info.get('segments'):
        print('[roi_extractor] FAIL -- ROI function(s) %s are never visited by the '
              'recorded execution path for %s. The trimmed path would be empty, '
              'which the circuit cannot accept as a witness -- aborting here instead '
              'of failing later inside the Java circuit compiler with a confusing '
              'error. This usually means the function was inlined away (common for '
              'small functions under -Os); try a larger/different function, e.g. '
              'via --function.' % (','.join(names), app_dir))
        return []
    return names


def usage():
    print('Usage: %s -a <app_dir> [options]' % sys.argv[0])
    print('  -a <path>           Application directory (output of extractor.py, plus')
    print('                      a compiled "main" binary)')
    print('  --top-n <num>       Number of ROI functions for auto-detection (default: 1)')
    print('  --provider <name>   LLM provider for auto-detection: "anthropic" or "gemini"')
    print('                      (default: ROI_DETECTOR_PROVIDER env var, else "anthropic")')
    print('  --model <name>      Model id to use for LLM-based ROI detection (meaning')
    print('                      depends on --provider -- see roi_detector.py --help)')
    print('  --heuristic-only    Skip the LLM call, use the static heuristic directly')
    print('  --function <names>  Comma-separated function names -- manual override that')
    print('                      skips detection entirely and uses these as the ROI')
    print('  --force-redetect    Ignore any cached ROI selection for this app_dir and')
    print('                      query the detector fresh (see roi_detector.py)')


if __name__ == '__main__':
    app_dir = None
    top_n = 1
    model = None
    provider = None
    heuristic_only = False
    func_names = None
    force_redetect = False
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'ha:',
                                    ['top-n=', 'model=', 'provider=', 'heuristic-only',
                                     'function=', 'force-redetect'])
    except getopt.GetoptError as err:
        print(err); usage(); sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            usage(); sys.exit()
        elif opt == '-a':
            app_dir = arg
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
    if not app_dir:
        usage(); sys.exit(2)

    result = extract_roi(app_dir, top_n=top_n, model=model, provider=provider,
                          force_heuristic=heuristic_only, func_names=func_names,
                          force_redetect=force_redetect)
    sys.exit(0 if result else 1)
