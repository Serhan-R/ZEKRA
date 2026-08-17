#!/usr/bin/python3
"""
ZEKRA CFG pruner
==================================
Reads the files already written by extractor.py and produces a pruned
adjacency list, removing nodes that are irrelevant to the recorded path.

Five pruning strategies (--mode):

  path          Keep only the exact nodes on the recorded execution path.
                Produces the smallest possible graph; good for circuit-size
                testing, but drops all alternative branches.

  forward       Keep all nodes forward-reachable from the initial node in
                the full CFG (via CFGFast edges). Conservative upper bound.

  bidir         [DEFAULT] Bidirectional slice: keep nodes that are both
                reachable FROM the initial node AND can reach the final node
                in the full CFG. Removes dead code that can never appear in
                any valid initial→final execution while preserving every
                branch that could legitimately be taken with different inputs.
                Most appropriate for ZEKRA's security model.

  region        Security-region attestation. Restricts the attested CFG to
                one or more user-specified address ranges or function names.
                Adds synthetic virtual_entry / virtual_exit nodes so the
                circuit still has a single initial and final node. All ROI
                visits in the execution path are concatenated into one path
                (option B): virtual_entry → visit1 → virtual_exit →
                virtual_entry → visit2 → ...

  region_bidir  Like region, the ROI is still one or more user-specified
                functions/address ranges. Unlike region, the pruned CFG is
                NOT restricted to only the ROI's own nodes -- instead it runs
                a bidirectional reachability search using the ROI as the
                pivot in both directions (start→ROI and ROI→end) and keeps
                the union of the ROI with both slices. No virtual entry/exit
                nodes are needed -- the program's real initial/final nodes
                stay in the graph, so the recorded path is preserved as-is.
                Produces a larger, more "meaningful" CFG than region (many
                real branches survive), while still being anchored on the
                same ROI detection step.

  region_trace  region_bidir augmented with the dynamic execution trace.
                Runs the same ROI-anchored bidirectional static slice as
                region_bidir, then unions in every unique node the execution
                actually visited. Any node that bidir would have pruned but
                that the trace visited is added back. This eliminates the
                two failure modes that region_bidir works around with a
                sentinel: translator failures (return destination not in
                pruned graph) and shadow stack imbalances (callee pruned
                so its RET disappears). Requires --function or --addr-range
                to identify the ROI, same as region_bidir.

Inputs  (from extractor.py output):
  <app_dir>/adjlist        — hex-address adjacency list (full CFG)
  <app_dir>/recorded_path  — execution path with initial/final nodes
  <app_dir>/main           — compiled ELF binary (needed for --function lookup)

Outputs (written into the same directory):
  <app_dir>/adjlist_pruned           — pruned adjacency list (hex addresses)
  <app_dir>/numified_adjlist_pruned  — pruned adjlist with integer labels
  <app_dir>/translator_pruned        — hex addresses in new label order
  <app_dir>/numified_path_pruned     — execution path with new labels
  <app_dir>/cfg_pruned.dot           — DOT for visualisation
  <app_dir>/cfg_pruned.svg           — SVG if `dot` CLI is available

Usage:
  # Standard modes
  python3 prune_cfg.py -a embench-iot-applications/crc32
  python3 prune_cfg.py -a embench-iot-applications/crc32 --mode path
  python3 prune_cfg.py -a embench-iot-applications/crc32 --mode forward
  python3 prune_cfg.py -d embench-iot-applications/

  # Region mode — by function name (requires nm, binary at <app_dir>/main)
  python3 prune_cfg.py -a embench-iot-applications/picojpeg --mode region \\
      --function "pjpeg_decode_mcu,pjpeg_decode_init"

  # Region mode — by address range
  python3 prune_cfg.py -a embench-iot-applications/picojpeg --mode region \\
      --addr-range "0x401200-0x401800,0x402000-0x402500"

  # Region mode — combine both
  python3 prune_cfg.py -a embench-iot-applications/picojpeg --mode region \\
      --function benchmark_body --addr-range "0x401200-0x401800"

  # Region-bidir mode — same ROI selection, richer merged CFG
  python3 prune_cfg.py -a embench-iot-applications/picojpeg --mode region_bidir \\
      --function "pjpeg_decode_mcu,pjpeg_decode_init"
"""

import os, sys, getopt, subprocess, shutil
import networkx as nx

# ── colour palette ────────────────────────────────────────────────────────────
COLOUR_INITIAL        = '#27ae60'
COLOUR_FINAL          = '#e74c3c'
COLOUR_PATH           = '#e67e22'
COLOUR_DEFAULT        = '#4a90d9'
COLOUR_PATH_EDGE      = '#8b0000'
COLOUR_EDGE           = '#888888'
COLOUR_VIRTUAL_ENTRY  = '#9b59b6'
COLOUR_VIRTUAL_EXIT   = '#8e44ad'
BG                    = '#1a1a2e'

# Synthetic addresses for virtual entry/exit nodes in region mode.
# Chosen to be above any real code address (which fits in 24 bits = 0xFFFFFF).
VIRTUAL_ENTRY = 0xFFFFFE00
VIRTUAL_EXIT  = 0xFFFFFE01


# ── file readers ──────────────────────────────────────────────────────────────

def read_adjlist(path: str) -> nx.DiGraph:
    G = nx.DiGraph()
    with open(path) as f:
        for line in f:
            tokens = line.split()
            if not tokens:
                continue
            src = int(tokens[0], 16)
            G.add_node(src)
            for tok in tokens[1:]:
                G.add_edge(src, int(tok, 16))
    return G


def read_recorded_path(path: str) -> dict:
    """
    Parse recorded_path and extract:
      - initial / final node addresses (int)
      - sequence: full ordered list of addresses visited (with repeats)
      - path_nodes: set of all visited addresses
      - path_edges: set of (src, dst) int pairs from consecutive pairs
      - transitions: list of (jumpkind, dst, ret_or_None)
    """
    with open(path) as f:
        lines = [l.rstrip() for l in f if l.strip()]

    header  = lines[0].split()
    initial = int(header[0].split('=')[1], 16)
    final   = int(header[1].split('=')[1], 16)

    transitions = []
    sequence = [initial]
    for line in lines[1:]:
        parts = line.split()
        jumpkind = parts[0]
        dst = int(parts[1], 16)
        ret = int(parts[2], 16) if jumpkind == 'call' else None
        transitions.append((jumpkind, dst, ret))
        sequence.append(dst)

    path_edges = set(zip(sequence[:-1], sequence[1:]))
    path_nodes = set(sequence)

    return {
        'initial':     initial,
        'final':       final,
        'sequence':    sequence,
        'path_nodes':  path_nodes,
        'path_edges':  path_edges,
        'transitions': transitions,
        'raw_lines':   lines,
    }


# ── region helpers ────────────────────────────────────────────────────────────

def parse_addr_ranges(addr_range_str: str) -> list:
    """
    Parse a comma-separated list of address ranges like
    "0x401200-0x401800,0x402000-0x402500".
    Returns list of (start_int, end_int) tuples (end is exclusive).
    """
    ranges = []
    for part in addr_range_str.split(','):
        part = part.strip()
        if not part:
            continue
        lo, hi = part.split('-')
        ranges.append((int(lo.strip(), 16), int(hi.strip(), 16)))
    return ranges


# ── address-space reconciliation ──────────────────────────────────────────
# `nm` reports a binary's linked (file) addresses, but angr/CLE rebases PIE
# binaries (gcc's default) to a runtime base -- e.g. nm says `main` is at
# 0x1060, but adjlist/translator (built from angr's CFG) have it at
# 0x401060. Uncorrected, --function/--mode region lookups would silently
# match zero CFG nodes on any PIE app. detect_rebase_delta() below
# calibrates the real per-app delta against adjlist/translator instead of
# hard-coding it; candidates are angr/CLE's default PIE base (0x400000) and
# 0 (non-PIE/static, unrebased).
CANDIDATE_REBASE_DELTAS = (0x400000, 0)


def _read_node_addresses(app_dir: str) -> set:
    """All addresses already recorded as real CFG nodes for this app, pooled
    from both adjlist and translator (reading both maximizes coverage and
    makes the delta calibration below robust even if one file is sparse)."""
    addrs = set()
    adjlist_path = os.path.join(app_dir, 'adjlist')
    if os.path.exists(adjlist_path):
        addrs |= set(read_adjlist(adjlist_path).nodes())
    translator_path = os.path.join(app_dir, 'translator')
    if os.path.exists(translator_path):
        with open(translator_path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    addrs.add(int(line, 16))
                except ValueError:
                    continue
    return addrs


def detect_rebase_delta(app_dir: str, binary_path: str = None) -> int:
    """
    Returns the best-scoring address delta between nm's raw/linked function
    addresses and the CFG's actual (possibly angr/CLE-rebased) address
    space, calibrated against this app's own adjlist/translator. Returns 0
    if there isn't enough data to calibrate against (in which case
    addresses are used as-is -- the previous, pre-correction behavior).
    """
    binary_path = binary_path or os.path.join(app_dir, 'main')
    if not os.path.exists(binary_path):
        return 0
    result = subprocess.run(['nm', '--defined-only', '-S', binary_path],
                            capture_output=True, text=True)
    func_starts = []
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[2].upper() in ('T', 'W'):
            try:
                addr = int(parts[0], 16)
                size = int(parts[1], 16)
                if size > 0:
                    func_starts.append(addr)
            except ValueError:
                continue
    node_addrs = _read_node_addresses(app_dir)
    if not func_starts or not node_addrs:
        return 0

    best_delta, best_score = 0, -1
    for delta in CANDIDATE_REBASE_DELTAS:
        score = sum(1 for addr in func_starts if (addr + delta) in node_addrs)
        if score > best_score:
            best_delta, best_score = delta, score
    return best_delta


def lookup_function_ranges(binary_path: str, func_names: list, app_dir: str = None) -> list:
    """
    Use nm to find address ranges of named functions in the binary.
    Returns list of (start, end, name) tuples.

    If app_dir is given, the returned addresses are additionally corrected
    for the angr/CLE PIE rebase delta (see "address-space reconciliation"
    above) by calibrating against the CFG node addresses already recorded
    in <app_dir>/adjlist and <app_dir>/translator. When app_dir is omitted,
    behavior is unchanged (raw nm addresses, no correction) -- preserved
    for backward compatibility with any caller that already does its own
    address-space reconciliation.
    """
    if not os.path.exists(binary_path):
        raise FileNotFoundError(f"Binary not found at {binary_path} — "
                                f"needed for --function lookup")
    result = subprocess.run(
        ['nm', '--defined-only', '-S', binary_path],
        capture_output=True, text=True
    )
    found = []
    name_set = set(func_names)
    for line in result.stdout.splitlines():
        parts = line.split()
        # nm -S output: address size type name
        if len(parts) >= 4 and parts[2].upper() in ('T', 'W'):
            try:
                addr = int(parts[0], 16)
                size = int(parts[1], 16)
                name = parts[3]
                if name in name_set:
                    found.append((addr, addr + size, name))
            except ValueError:
                continue
    missing = name_set - {name for _, _, name in found}
    if missing:
        print(f"  [!] Functions not found in symbol table: {missing}")
        print(f"      Available functions (T/W):")
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[2].upper() in ('T', 'W') and int(parts[1], 16) > 0:
                print(f"        {parts[3]:40s} {parts[0]}")

    if app_dir is not None and found:
        delta = detect_rebase_delta(app_dir, binary_path)
        if delta:
            print(f"  [prune] PIE rebase delta detected: +{hex(delta)} "
                  f"(nm addresses shifted to match CFG/adjlist address space)")
        found = [(start + delta, end + delta, name) for start, end, name in found]

    return found


def build_in_region_fn(ranges: list):
    """Returns a function that tests whether an address is in any of the ranges."""
    def in_region(addr: int) -> bool:
        return any(lo <= addr < hi for lo, hi in ranges)
    return in_region


# ── pruning strategies ────────────────────────────────────────────────────────

def prune_path(G: nx.DiGraph, path_info: dict, **kwargs) -> tuple:
    P = nx.DiGraph()
    for n in path_info['path_nodes']:
        P.add_node(n)
    for u, v in path_info['path_edges']:
        P.add_edge(u, v)
    return P, path_info


def prune_forward(G: nx.DiGraph, path_info: dict, **kwargs) -> tuple:
    initial = path_info['initial']
    if initial not in G:
        raise ValueError(f"Initial node {hex(initial)} not in CFG graph")
    reachable = nx.descendants(G, initial) | {initial}
    return G.subgraph(reachable).copy(), path_info


def prune_bidir(G: nx.DiGraph, path_info: dict, **kwargs) -> tuple:
    initial = path_info['initial']
    final   = path_info['final']

    if initial not in G:
        raise ValueError(f"Initial node {hex(initial)} not in CFG graph")
    if final not in G:
        print(f"  [!] Final node {hex(final)} not in static CFG — "
              f"falling back to forward slice")
        return prune_forward(G, path_info)

    forward  = nx.descendants(G, initial) | {initial}
    backward = nx.ancestors(G, final)     | {final}
    keep     = forward & backward
    return G.subgraph(keep).copy(), path_info


def _reachable_from_any(G: nx.DiGraph, sources: set) -> set:
    """
    Multi-source forward reachability: nodes reachable from ANY node in
    `sources`, inclusive of `sources` itself. Equivalent to
    union(nx.descendants(G, s) for s in sources) | sources, but done as a
    single BFS instead of one BFS per source.
    """
    from collections import deque
    seen  = {s for s in sources if s in G}
    queue = deque(seen)
    while queue:
        u = queue.popleft()
        for v in G.successors(u):
            if v not in seen:
                seen.add(v)
                queue.append(v)
    return seen


def _reachable_to_any(G: nx.DiGraph, sinks: set) -> set:
    """
    Multi-source backward reachability: nodes that can reach ANY node in
    `sinks`, inclusive of `sinks` itself. Equivalent to
    union(nx.ancestors(G, s) for s in sinks) | sinks, but done as a single
    BFS (over predecessors) instead of one BFS per sink.
    """
    from collections import deque
    seen  = {s for s in sinks if s in G}
    queue = deque(seen)
    while queue:
        u = queue.popleft()
        for v in G.predecessors(u):
            if v not in seen:
                seen.add(v)
                queue.append(v)
    return seen


def _find_roi_segments(states: list, in_region_fn) -> list:
    """
    Contiguous runs of in-region states within an execution sequence.
    Returns a list of (start_idx, end_idx) pairs (inclusive indices into
    `states`). Used both to detect whether the recorded path ever visits
    the ROI at all, and (in `region` mode) to drive the path-stitching.
    """
    segments  = []
    in_roi    = False
    seg_start = None
    for i, state in enumerate(states):
        if in_region_fn(state):
            if not in_roi:
                seg_start = i
                in_roi = True
        else:
            if in_roi:
                segments.append((seg_start, i - 1))
                in_roi = False
    if in_roi:
        segments.append((seg_start, len(states) - 1))
    return segments


def prune_region_bidir(G: nx.DiGraph, path_info: dict,
                       in_region_fn=None, **kwargs) -> tuple:
    """
    ROI-anchored bidirectional slice (see module docstring for "region_bidir").

    roi_nodes is computed exactly like `region` (same --function/--addr-range
    resolution). From there, instead of throwing away every non-ROI node:

      start_to_roi = (forward-reachable from the program's real initial node)
                    ∩ (backward-reachable INTO the ROI from anywhere)
      roi_to_end   = (forward-reachable OUT of the ROI to anywhere)
                    ∩ (backward-reachable from the program's real final node)
      keep         = roi_nodes ∪ start_to_roi ∪ roi_to_end

    No virtual entry/exit nodes are introduced: `initial`/`final` are real
    CFG nodes and (by construction) every node the recorded run actually
    visited lies on a real initial→...→final walk, so it is necessarily an
    ancestor-or-self of the ROI nodes it walks into and a descendant-or-self
    of the ROI nodes it walks out of -- i.e. already inside `keep`. That
    means path_info needs no trimming/re-stitching; it is returned
    unchanged (mirroring path/forward/bidir), just with a `segments` field
    added so callers can still detect "ROI never visited" the same way
    `region` mode's callers already do.
    """
    if in_region_fn is None:
        raise ValueError("--mode region_bidir requires --function or --addr-range")

    roi_nodes = {n for n in G.nodes() if in_region_fn(n)}
    if not roi_nodes:
        raise ValueError("No CFG nodes fall within the specified region. "
                         "Check your address ranges or function names.")

    initial = path_info['initial']
    final   = path_info['final']
    if initial not in G:
        raise ValueError(f"Initial node {hex(initial)} not in CFG graph")

    roi_descendants = _reachable_from_any(G, roi_nodes)  # ROI ∪ its forward reach
    roi_ancestors   = _reachable_to_any(G, roi_nodes)    # ROI ∪ its backward reach

    forward_from_initial = nx.descendants(G, initial) | {initial}
    start_to_roi = forward_from_initial & roi_ancestors

    if final in G:
        backward_from_final = nx.ancestors(G, final) | {final}
        roi_to_end = roi_descendants & backward_from_final
    else:
        print(f"  [!] Final node {hex(final)} not in static CFG — "
              f"keeping everything forward-reachable from the ROI instead "
              f"of intersecting with an end-side slice")
        roi_to_end = roi_descendants

    keep = roi_nodes | start_to_roi | roi_to_end

    # Angr represents "after this call returns, go here" as a fake-return
    # edge attached to the CALL block (caller side), not to the callee's
    # RET instruction. This means the bidir slice never sees a path
    # ROI→ret_addr and evicts those return-address nodes, even though
    # execution must pass through them after the callee returns.
    # Fix: explicitly keep every call's ret_addr that is a real CFG node.
    call_ret_addrs = {
        ret for (jk, _dst, ret) in path_info.get('transitions', [])
        if jk == 'call' and ret is not None and ret in G
    }
    fake_ret_added = call_ret_addrs - keep
    if fake_ret_added:
        print(f"  Fake-ret nodes  : {len(fake_ret_added)} return address(es) "
              f"added back (angr fake-return edge targets missing from bidir slice)")
    else:
        print(f"  Fake-ret nodes  : 0 (all call return addresses already in slice)")
    keep = keep | call_ret_addrs

    P = G.subgraph(keep).copy()

    # Diagnostic-only: confirms/reports that the recorded path visits the
    # ROI. No stitching needed (path_info passes through unchanged below).
    segments = _find_roi_segments(path_info['sequence'], in_region_fn)
    if not segments:
        print("  [!] WARNING: execution path never enters the specified region.")
    print(f"  ROI visits      : {len(segments)} "
          f"({'→'.join(str(e-s+1)+' steps' for s,e in segments[:3])}"
          f"{'...' if len(segments)>3 else ''})")
    print(f"  Start→ROI nodes : {len(start_to_roi)}   "
          f"ROI→End nodes   : {len(roi_to_end)}")

    new_path_info = dict(path_info)
    new_path_info['segments'] = segments
    return P, new_path_info


def prune_region(G: nx.DiGraph, path_info: dict,
                 in_region_fn=None, **kwargs) -> tuple:
    """
    Keep only CFG nodes within the specified region, add virtual entry/exit
    nodes, and trim the execution path to only in-region transitions.
    Multiple ROI visits are concatenated (option B):
      virtual_entry → visit1 → virtual_exit → virtual_entry → visit2 → ...
    """
    if in_region_fn is None:
        raise ValueError("--mode region requires --function or --addr-range")

    # ── build pruned CFG ─────────────────────────────────────────────────────
    roi_nodes = {n for n in G.nodes() if in_region_fn(n)}

    if not roi_nodes:
        raise ValueError("No CFG nodes fall within the specified region. "
                         "Check your address ranges or function names.")

    P = G.subgraph(roi_nodes).copy()

    # Add virtual nodes
    P.add_node(VIRTUAL_ENTRY)
    P.add_node(VIRTUAL_EXIT)

    # virtual_entry → all ROI nodes whose predecessors are all outside ROI
    # (structural entry points of the region)
    for n in roi_nodes:
        preds = list(G.predecessors(n))
        if not preds or any(p not in roi_nodes for p in preds):
            P.add_edge(VIRTUAL_ENTRY, n)

    # all ROI nodes whose successors are all outside ROI → virtual_exit
    # (structural exit points of the region)
    for n in roi_nodes:
        succs = list(G.successors(n))
        if not succs or any(s not in roi_nodes for s in succs):
            P.add_edge(n, VIRTUAL_EXIT)

    # virtual_exit → virtual_entry: allows multiple ROI visits in the path
    P.add_edge(VIRTUAL_EXIT, VIRTUAL_ENTRY)

    # ── trim execution path ──────────────────────────────────────────────────
    transitions   = path_info['transitions']
    states        = path_info['sequence']  # states[i] = state before transition i

    segments = _find_roi_segments(states, in_region_fn)

    if not segments:
        print("  [!] WARNING: execution path never enters the specified region.")
        print("              The trimmed path will be empty.")

    print(f"  ROI visits      : {len(segments)} "
          f"({'→'.join(str(e-s+1)+' steps' for s,e in segments[:3])}"
          f"{'...' if len(segments)>3 else ''})")

    # Build trimmed transition list (option B: concatenate all visits)
    trimmed_transitions = []
    trimmed_sequence    = [VIRTUAL_ENTRY]

    for seg_idx, (start, end) in enumerate(segments):
        # Enter ROI: virtual_entry → states[start]
        trimmed_transitions.append(('jump', states[start], None))
        trimmed_sequence.append(states[start])

        # Within ROI: emit original transitions for states[start..end-1]
        for i in range(start, end):
            jk, dst, ret = transitions[i]
            trimmed_transitions.append((jk, dst, ret))
            trimmed_sequence.append(dst)

        # Exit ROI: last_roi_state → virtual_exit
        trimmed_transitions.append(('jump', VIRTUAL_EXIT, None))
        trimmed_sequence.append(VIRTUAL_EXIT)

        # Bridge to next segment
        if seg_idx < len(segments) - 1:
            trimmed_transitions.append(('jump', VIRTUAL_ENTRY, None))
            trimmed_sequence.append(VIRTUAL_ENTRY)

    # Build updated path_info for the region
    path_edges = set(zip(trimmed_sequence[:-1], trimmed_sequence[1:]))
    path_nodes = set(trimmed_sequence)

    new_path_info = {
        'initial':     VIRTUAL_ENTRY,
        'final':       VIRTUAL_EXIT,
        'sequence':    trimmed_sequence,
        'path_nodes':  path_nodes,
        'path_edges':  path_edges,
        'transitions': trimmed_transitions,
        'raw_lines':   path_info['raw_lines'],
        'is_region':   True,
        'segments':    segments,
    }

    return P, new_path_info


def prune_region_trace(G: nx.DiGraph, path_info: dict,
                       in_region_fn=None, **kwargs) -> tuple:
    """
    ROI-anchored bidirectional slice augmented with the dynamic execution trace
    (region_trace mode).

    This is region_bidir with one addition: after computing the static
    start→ROI→end slice, the unique nodes from the actual execution trace are
    unioned in. The result is that any node the execution visited but that
    static reachability missed is added back, while the graph still stays
    anchored on and sized around the ROI.

    This eliminates the two failure modes caused by region_bidir pruning nodes
    that appear in the actual execution:
      - Translator failure: a RET whose destination was pruned out has no entry
        in the translator. With region_trace, every return destination in the
        trace is in the graph.
      - Shadow stack imbalance: a CALL whose callee was pruned loses its
        matching RET. With region_trace, the callee's blocks are in the graph
        so every push has a corresponding pop.

    Requires --function or --addr-range to identify the ROI (same as
    region_bidir).
    """
    if in_region_fn is None:
        raise ValueError("--mode region_trace requires --function or --addr-range")

    # Step 1: run bidir to get the static ROI-anchored slice
    P_bidir, bidir_path_info = prune_region_bidir(G, path_info,
                                                   in_region_fn=in_region_fn,
                                                   **kwargs)
    bidir_nodes = set(P_bidir.nodes())

    # Step 2: union with all unique nodes from the dynamic trace
    trace_nodes = {n for n in path_info['path_nodes'] if n in G}
    keep = bidir_nodes | trace_nodes

    extra = trace_nodes - bidir_nodes
    if extra:
        print(f"  Trace-added nodes: {len(extra)} node(s) present in trace "
              f"but absent from bidir slice — added back to fix shadow stack / "
              f"translator failures")
    else:
        print(f"  Trace-added nodes: 0 (bidir slice already covers full trace)")

    missing_from_cfg = path_info['path_nodes'] - set(G.nodes())
    if missing_from_cfg:
        print(f"  [!] {len(missing_from_cfg)} trace node(s) absent from static CFG "
              f"(angr missed them): "
              f"{[hex(n) for n in sorted(missing_from_cfg)[:5]]}"
              f"{'...' if len(missing_from_cfg) > 5 else ''}")

    P = G.subgraph(keep).copy()
    return P, bidir_path_info


STRATEGIES = {
    'path':          prune_path,
    'forward':       prune_forward,
    'bidir':         prune_bidir,
    'region':        prune_region,
    'region_bidir':  prune_region_bidir,
    'region_trace':  prune_region_trace,
}


# ── writers ───────────────────────────────────────────────────────────────────

def write_adjlist(G: nx.DiGraph, path: str):
    with open(path, 'w') as f:
        for node in sorted(G.nodes()):
            succs = ' '.join(hex(s) for s in sorted(G.successors(node)))
            line  = hex(node) + (' ' + succs if succs else '')
            f.write(line + '\n')
    print(f"[prune] adjlist_pruned → {path}")


def write_numified_files(G_pruned: nx.DiGraph, path_info: dict, app_dir: str):
    """
    Assign new integer labels 1..N to pruned nodes (sorted by address).
    Label 0 is reserved as a dummy (EMPTY_DEST_ADDR sentinel).
    Virtual entry/exit nodes get labels at the high end (they have the
    highest addresses 0xFFFFFE00/01 so they naturally sort last).

    Writes:
      - translator_pruned        (hex addresses in new label order, 1-indexed)
      - numified_adjlist_pruned  (integer-label adjacency list)
      - numified_path_pruned     (execution path with new labels)
    """
    sorted_nodes  = sorted(G_pruned.nodes())
    addr_to_label = {addr: i + 1 for i, addr in enumerate(sorted_nodes)}
    n_pruned      = len(sorted_nodes)
    empty_label   = n_pruned + 1  # sentinel above all real labels

    is_region = path_info.get('is_region', False)

    # ── translator_pruned ────────────────────────────────────────────────────
    translator_path = os.path.join(app_dir, 'translator_pruned')
    with open(translator_path, 'w') as f:
        f.write('0x0\n')  # dummy label 0 (EMPTY_DEST_ADDR)
        for addr in sorted_nodes:
            f.write(hex(addr) + '\n')
    print(f"[prune] translator_pruned → {translator_path}  "
          f"({n_pruned} real + 1 dummy = {n_pruned+1} entries)")

    # ── numified_adjlist_pruned ──────────────────────────────────────────────
    numified_adjlist_path = os.path.join(app_dir, 'numified_adjlist_pruned')
    with open(numified_adjlist_path, 'w') as f:
        f.write('0\n')  # dummy label 0, no neighbors
        for addr in sorted_nodes:
            label = addr_to_label[addr]
            neighbor_labels = sorted(
                addr_to_label[succ]
                for succ in G_pruned.successors(addr)
                if succ in addr_to_label
            )
            line = str(label)
            if neighbor_labels:
                line += ' ' + ' '.join(str(l) for l in neighbor_labels)
            f.write(line + '\n')
    print(f"[prune] numified_adjlist_pruned → {numified_adjlist_path}")

    # ── numified_path_pruned ─────────────────────────────────────────────────
    initial      = path_info['initial']
    final        = path_info['final']
    initial_label = addr_to_label.get(initial, empty_label)
    final_label   = addr_to_label.get(final,   empty_label)

    numified_path_path = os.path.join(app_dir, 'numified_path_pruned')
    with open(numified_path_path, 'w') as f:
        f.write(f'initial_node={initial_label} final_node={final_label}\n')
        for jumpkind, dst_addr, ret_addr in path_info['transitions']:
            dst_label = addr_to_label.get(dst_addr, empty_label)
            if jumpkind == 'call':
                ret_label = (addr_to_label.get(ret_addr, empty_label)
                             if ret_addr is not None else empty_label)
            else:
                ret_label = empty_label
            f.write(f'{jumpkind} {dst_label} {ret_label}\n')
    print(f"[prune] numified_path_pruned → {numified_path_path}")

    # ── summary ──────────────────────────────────────────────────────────────
    print(f"\n  ┌─ Use these parameters for the pruned circuit ──────────────")
    print(f"  │  Labels: 0 (dummy), 1..{n_pruned} (real)")
    if is_region:
        ve_label = addr_to_label.get(VIRTUAL_ENTRY, '?')
        vx_label = addr_to_label.get(VIRTUAL_EXIT,  '?')
        print(f"  │  virtual_entry label={ve_label}  virtual_exit label={vx_label}")
    print(f"  │  --pad-adjlist-to >= {n_pruned+2}  (e.g. 500 to reuse existing circuit)")
    print(f"  │  --adjlist-len >= {n_pruned+2}  (in compile_circuit.py)")
    print(f"  │  --pad-path-to <your_path_len>")
    print(f"  └────────────────────────────────────────────────────────────")


def write_recorded_path_pruned(path_info: dict, app_dir: str):
    """
    Raw-hex-address counterpart of numified_path_pruned.

    Why this exists: circuit_input_formatter.py's --pruned mode swaps in
    *_pruned variants for the adjlist/numified-path/translator files, but
    by design never substitutes RECORDED_PATH_FILENAME -- the source
    comments call it "never changes" because for path/forward/bidir pruning
    modes the execution path's transitions are untouched (only the graph
    shrinks). Region mode is the exception: prune_region() actually trims
    and re-stitches the transition list itself (via VIRTUAL_ENTRY/EXIT
    boundary nodes), so the original recorded_path's transition count no
    longer matches the pruned path/circuit sizing. Without a pruned raw
    file, the full unpruned recorded_path gets read into a circuit array
    sized for the pruned path, overflowing it (e.g. "Index 11 out of bounds
    for length 11" when the pruned path has 11 transitions but the full
    file has 21).

    This writes that missing file, reusing the exact transitions
    write_numified_files() already derives from prune_region() -- just
    emitting the raw hex addresses instead of translated integer labels,
    matching the original recorded_path file's format exactly:
      header: 'initial_node=0x.. final_node=0x..'
      lines:  '<jumpkind> <dst_hex> <ret_hex>'   (call)
              '<jumpkind> <dst_hex>'             (jump/ret)
    This format is what circuit_input_formatter.py's read_path() +
    binify_path() expect (binify_path parses dst/ret via int(x, 16)).
    """
    initial = path_info['initial']
    final   = path_info['final']

    out_path = os.path.join(app_dir, 'recorded_path_pruned')
    with open(out_path, 'w') as f:
        f.write(f'initial_node={hex(initial)} final_node={hex(final)}\n')
        for jumpkind, dst_addr, ret_addr in path_info['transitions']:
            if jumpkind == 'call':
                f.write(f'{jumpkind} {hex(dst_addr)} {hex(ret_addr)}\n')
            else:
                f.write(f'{jumpkind} {hex(dst_addr)}\n')
    print(f"[prune] recorded_path_pruned → {out_path}")


def write_dot(G: nx.DiGraph, path_info: dict, dot_path: str):
    path_nodes = path_info['path_nodes']
    path_edges = path_info['path_edges']
    initial    = path_info['initial']
    final      = path_info['final']
    is_region  = path_info.get('is_region', False)

    def node_colour(n):
        if n == VIRTUAL_ENTRY:  return COLOUR_VIRTUAL_ENTRY
        if n == VIRTUAL_EXIT:   return COLOUR_VIRTUAL_EXIT
        if n == initial:        return COLOUR_INITIAL
        if n == final:          return COLOUR_FINAL
        if n in path_nodes:     return COLOUR_PATH
        return COLOUR_DEFAULT

    def node_label(n):
        if n == VIRTUAL_ENTRY: return 'virtual_entry'
        if n == VIRTUAL_EXIT:  return 'virtual_exit'
        return hex(n)

    def node_shape(n):
        if n in (VIRTUAL_ENTRY, VIRTUAL_EXIT): return 'diamond'
        return 'box'

    lines = [
        'digraph CFG_pruned {',
        f'    graph [rankdir=TB fontname="monospace" bgcolor="{BG}" '
        f'label="Pruned CFG ({"region" if path_info.get("is_region", False) else ""}) '
        f': {G.number_of_nodes()} nodes"];',
        '    node  [style=filled fontname="monospace" fontsize=9];',
        '    edge  [fontname="monospace" fontsize=8];',
    ]
    for n in sorted(G.nodes()):
        colour = node_colour(n)
        shape  = node_shape(n)
        lines.append(f'    n{n} [label="{node_label(n)}" shape={shape} '
                     f'fillcolor="{colour}" fontcolor="white"];')
    for u, v in G.edges():
        on_path = (u, v) in path_edges
        colour  = COLOUR_PATH_EDGE if on_path else COLOUR_EDGE
        width   = '2.5' if on_path else '0.8'
        lines.append(f'    n{u} -> n{v} [color="{colour}" penwidth={width}];')
    lines.append('}')

    with open(dot_path, 'w') as f:
        f.write('\n'.join(lines))
    print(f"[prune] DOT → {dot_path}")


def render_svg(dot_path: str, svg_path: str):
    if shutil.which('dot') is None:
        print('[prune] `dot` not on PATH — skipping SVG (apt install graphviz)')
        return
    try:
        subprocess.run(['dot', '-Tsvg', dot_path, '-o', svg_path],
                       check=True, capture_output=True)
        print(f"[prune] SVG → {svg_path}")
    except subprocess.CalledProcessError as e:
        print(f"[prune] dot failed: {e.stderr.decode()[:200]}")


# ── stats printer ─────────────────────────────────────────────────────────────

def print_stats(G_full: nx.DiGraph, G_pruned: nx.DiGraph,
                path_info: dict, mode: str):
    n_full    = G_full.number_of_nodes()
    e_full    = G_full.number_of_edges()
    # Exclude virtual nodes from counts for fair comparison
    real_nodes = [n for n in G_pruned.nodes()
                  if n not in (VIRTUAL_ENTRY, VIRTUAL_EXIT)]
    n_pruned  = len(real_nodes)
    e_pruned  = sum(1 for u, v in G_pruned.edges()
                    if u not in (VIRTUAL_ENTRY, VIRTUAL_EXIT)
                    and v not in (VIRTUAL_ENTRY, VIRTUAL_EXIT))
    n_removed = n_full - n_pruned
    e_removed = e_full - e_pruned

    print(f"\n  Mode            : {mode}")
    print(f"  Full CFG        : {n_full} nodes, {e_full} edges")
    print(f"  Pruned CFG      : {n_pruned} real nodes, {e_pruned} edges"
          f"{' + 2 virtual nodes' if mode == 'region' else ''}")
    print(f"  Removed         : {n_removed} nodes ({n_removed/n_full*100:.0f}%), "
          f"{e_removed} edges ({e_removed/e_full*100:.0f}%)")

    if mode == 'region':
        # For region mode check path nodes excluding virtual
        real_path_nodes = {n for n in path_info['path_nodes']
                           if n not in (VIRTUAL_ENTRY, VIRTUAL_EXIT)}
        missing = [hex(n) for n in real_path_nodes if n not in G_pruned]
    else:
        missing = [hex(n) for n in path_info['path_nodes'] if n not in G_pruned]

    if missing:
        print(f"  [!] WARNING: {len(missing)} path nodes missing: {missing}")
    else:
        real_count = len([n for n in path_info['path_nodes']
                          if n not in (VIRTUAL_ENTRY, VIRTUAL_EXIT)])
        print(f"  Path integrity  : OK (all {real_count} real path nodes preserved)")

    if mode != 'region':
        missing_edges = [(hex(u), hex(v)) for u, v in path_info['path_edges']
                         if not G_pruned.has_edge(u, v)]
        if missing_edges:
            print(f"  [!] WARNING: {len(missing_edges)} path edges missing:")
            for u, v in missing_edges:
                print(f"       {u} -> {v}")
        else:
            print(f"  Edge integrity  : OK "
                  f"(all {len(path_info['path_edges'])} path edges preserved)")


# ── main pipeline ─────────────────────────────────────────────────────────────

def prune_dir(app_dir: str, mode: str = 'bidir',
              func_names: list = None, addr_ranges: list = None):
    adjlist_file = os.path.join(app_dir, 'adjlist')
    path_file    = os.path.join(app_dir, 'recorded_path')

    if not os.path.exists(adjlist_file):
        print(f"[!] {adjlist_file} not found — run extractor.py first"); return
    if not os.path.exists(path_file):
        print(f"[!] {path_file} not found — run extractor.py first"); return

    print(f"\n[prune] {app_dir}")

    G_full    = read_adjlist(adjlist_file)
    path_info = read_recorded_path(path_file)

    # ── region / region_bidir modes: build in_region_fn ─────────────────────
    in_region_fn = None
    if mode in ('region', 'region_bidir', 'region_trace'):
        ranges = list(addr_ranges or [])

        # Resolve function names via nm
        if func_names:
            binary_path = os.path.join(app_dir, 'main')
            func_ranges = lookup_function_ranges(binary_path, func_names, app_dir=app_dir)
            for start, end, name in func_ranges:
                print(f"  Function '{name}': {hex(start)} – {hex(end-1)} "
                      f"({end-start} bytes)")
                ranges.append((start, end))

        if not ranges:
            print(f"[!] No valid address ranges for {mode} mode. "
                  "Use --function or --addr-range."); return

        print(f"  Region ranges   : {[(hex(s), hex(e)) for s,e in ranges]}")
        in_region_fn = build_in_region_fn(ranges)

    strategy = STRATEGIES[mode]
    G_pruned, new_path_info = strategy(
        G_full, path_info, in_region_fn=in_region_fn
    )

    print_stats(G_full, G_pruned, new_path_info, mode)

    write_adjlist(G_pruned, os.path.join(app_dir, 'adjlist_pruned'))
    write_numified_files(G_pruned, new_path_info, app_dir)
    write_recorded_path_pruned(new_path_info, app_dir)
    write_dot(G_pruned, new_path_info, os.path.join(app_dir, 'cfg_pruned.dot'))
    render_svg(os.path.join(app_dir, 'cfg_pruned.dot'),
               os.path.join(app_dir, 'cfg_pruned.svg'))

    # Returned so callers (e.g. roi_extractor.extract_roi()) can inspect
    # new_path_info['segments'] -- in region mode, an empty list means the
    # recorded execution path never actually entered the requested region
    # (already printed above as a "[!] WARNING" by the region strategy), and
    # callers should treat that as a hard failure rather than proceeding with
    # a witness that has zero real transitions in it.
    return new_path_info


# ── CLI ───────────────────────────────────────────────────────────────────────

def usage():
    print(f'Usage: {sys.argv[0]} -a <app_dir> | -d <apps_dir> [options]')
    print('  -a <path>                     Single application directory')
    print('  -d <path>                     Directory of multiple application folders')
    print('  --mode path|forward|bidir|region|region_bidir|region_trace')
    print('                                Pruning strategy (default: bidir)')
    print()
    print('  Region mode options (--mode region | region_bidir):')
    print('  --function <name1,name2,...>  Function names to include in ROI')
    print('                                (requires nm and <app_dir>/main binary)')
    print('  --addr-range <r1,r2,...>      Address ranges, e.g. 0x401200-0x401800')
    print('                                Multiple ranges separated by commas')


if __name__ == '__main__':
    app_dir    = apps_dir  = None
    mode       = 'bidir'
    func_names = []
    addr_ranges = []

    try:
        opts, _ = getopt.getopt(
            sys.argv[1:], 'ha:d:',
            ['mode=', 'function=', 'addr-range=']
        )
    except getopt.GetoptError as e:
        print(e); usage(); sys.exit(2)

    for opt, arg in opts:
        if opt == '-h':
            usage(); sys.exit()
        elif opt == '-a':
            app_dir = arg.rstrip('/')
        elif opt == '-d':
            apps_dir = arg.rstrip('/')
        elif opt == '--mode':
            if arg not in STRATEGIES:
                print(f"Unknown mode '{arg}'. Choose: {list(STRATEGIES)}")
                sys.exit(2)
            mode = arg
        elif opt == '--function':
            func_names = [f.strip() for f in arg.split(',') if f.strip()]
        elif opt == '--addr-range':
            addr_ranges = parse_addr_ranges(arg)

    if mode in ('region', 'region_bidir') and not func_names and not addr_ranges:
        print(f"[!] --mode {mode} requires --function or --addr-range")
        usage(); sys.exit(2)

    if app_dir:
        prune_dir(app_dir, mode, func_names=func_names, addr_ranges=addr_ranges)
    elif apps_dir:
        for entry in sorted(os.scandir(apps_dir), key=lambda e: e.name):
            if entry.is_dir():
                try:
                    prune_dir(entry.path, mode,
                              func_names=func_names, addr_ranges=addr_ranges)
                except Exception as e:
                    print(f'[!] {entry.path}: {e}')
    else:
        print('No directory specified.'); usage