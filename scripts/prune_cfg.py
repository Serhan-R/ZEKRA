#!/usr/bin/python3
"""
prune_cfg.py  —  ZEKRA CFG pruner
==================================
Reads the files already written by extractor.py and produces a pruned
adjacency list, removing nodes that are irrelevant to the recorded path.

Three pruning strategies (--mode):

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

Inputs  (from extractor.py output):
  <app_dir>/adjlist        — hex-address adjacency list (full CFG)
  <app_dir>/recorded_path  — execution path with initial/final nodes

Outputs (written into the same directory):
  <app_dir>/adjlist_pruned           — pruned adjacency list (hex addresses)
  <app_dir>/numified_adjlist_pruned  — pruned adjlist with integer labels
  <app_dir>/translator_pruned        — hex addresses in new label order
  <app_dir>/numified_path_pruned     — execution path with new labels
  <app_dir>/cfg_pruned.dot           — DOT for visualisation
  <app_dir>/cfg_pruned.svg           — SVG if `dot` CLI is available

After running, use circuit_input_formatter.py with --pruned and set
--pad-adjlist-to to the pruned node count printed by this script.

Usage:
  python3 prune_cfg.py -a embench-iot-applications/crc32
  python3 prune_cfg.py -a embench-iot-applications/crc32 --mode path
  python3 prune_cfg.py -a embench-iot-applications/crc32 --mode forward
  python3 prune_cfg.py -d embench-iot-applications/
"""

import os, sys, getopt, subprocess, shutil
import networkx as nx

# ── colour palette ────────────────────────────────────────────────────────────
COLOUR_INITIAL   = '#27ae60'
COLOUR_FINAL     = '#e74c3c'
COLOUR_PATH      = '#e67e22'
COLOUR_DEFAULT   = '#4a90d9'
COLOUR_PATH_EDGE = '#8b0000'
COLOUR_EDGE      = '#888888'
BG               = '#1a1a2e'


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
    """
    with open(path) as f:
        lines = [l.rstrip() for l in f if l.strip()]

    header  = lines[0].split()
    initial = int(header[0].split('=')[1], 16)
    final   = int(header[1].split('=')[1], 16)

    # Build full transition list: (jumpkind, dst, ret_or_None)
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
        'transitions': transitions,  # list of (jumpkind, dst, ret_or_None)
        'raw_lines':   lines,        # original lines for recorded_path passthrough
    }


# ── pruning strategies ────────────────────────────────────────────────────────

def prune_path(G: nx.DiGraph, path_info: dict) -> nx.DiGraph:
    P = nx.DiGraph()
    for n in path_info['path_nodes']:
        P.add_node(n)
    for u, v in path_info['path_edges']:
        P.add_edge(u, v)
    return P


def prune_forward(G: nx.DiGraph, path_info: dict) -> nx.DiGraph:
    initial = path_info['initial']
    if initial not in G:
        raise ValueError(f"Initial node {hex(initial)} not in CFG graph")
    reachable = nx.descendants(G, initial) | {initial}
    return G.subgraph(reachable).copy()


def prune_bidir(G: nx.DiGraph, path_info: dict) -> nx.DiGraph:
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
    return G.subgraph(keep).copy()


STRATEGIES = {
    'path':    prune_path,
    'forward': prune_forward,
    'bidir':   prune_bidir,
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
    Labels start from 1 to reserve 0 for the EMPTY_DEST_ADDR sentinel
    used by the ZEKRA circuit. empty_label = N+1 = ADJLIST_SIZE.
    Writes:
      - translator_pruned        (hex addresses in new label order, 1-indexed)
      - numified_adjlist_pruned  (integer-label adjacency list)
      - numified_path_pruned     (execution path with new labels)
    """
    sorted_nodes = sorted(G_pruned.nodes())
    # Labels start at 1 — label 0 is reserved for EMPTY_DEST_ADDR in the circuit.
    # A dummy entry for label 0 (no neighbors, address 0x0) is prepended to both
    # numified_adjlist_pruned and translator_pruned so that the formatter's phantom
    # node generator (which uses str(len(adjlist))) starts at N+1 and never
    # collides with any real label 1..N.
    addr_to_label = {addr: i + 1 for i, addr in enumerate(sorted_nodes)}
    n_pruned = len(sorted_nodes)
    # After adding dummy label 0, the adjlist has N+1 entries.
    # Phantom nodes from the formatter start at N+1 — no collision with 1..N.
    empty_label = n_pruned + 1  # sentinel: one above the highest real label

    # ── translator_pruned ────────────────────────────────────────────────────
    # Entry 0: dummy placeholder (0x0 = EMPTY_DEST_ADDR, never looked up in practice)
    # Entries 1..N: real node addresses in label order
    translator_path = os.path.join(app_dir, 'translator_pruned')
    with open(translator_path, 'w') as f:
        f.write('0x0\n')  # dummy label 0
        for addr in sorted_nodes:
            f.write(hex(addr) + '\n')
    print(f"[prune] translator_pruned → {translator_path}  ({n_pruned} real + 1 dummy = {n_pruned+1} entries)")

    # ── numified_adjlist_pruned ──────────────────────────────────────────────
    # Entry 0: dummy node (no neighbors)
    # Entries 1..N: real nodes with neighbor labels
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
    initial = path_info['initial']
    final   = path_info['final']
    initial_label = addr_to_label.get(initial, empty_label)
    final_label   = addr_to_label.get(final,   empty_label)

    numified_path_path = os.path.join(app_dir, 'numified_path_pruned')
    with open(numified_path_path, 'w') as f:
        f.write(f'initial_node={initial_label} final_node={final_label}\n')
        for jumpkind, dst_addr, ret_addr in path_info['transitions']:
            dst_label = addr_to_label.get(dst_addr, empty_label)
            if jumpkind == 'call':
                ret_label = addr_to_label.get(ret_addr, empty_label) if ret_addr is not None else empty_label
            else:
                ret_label = empty_label
            f.write(f'{jumpkind} {dst_label} {ret_label}\n')
    print(f"[prune] numified_path_pruned → {numified_path_path}")

    # ── summary for the user ─────────────────────────────────────────────────
    # numified_adjlist_pruned has N+1 entries (dummy label 0 + real labels 1..N)
    # Phantom labels start at N+1, so --pad-adjlist-to must be > N+1.
    # Use 500 to reuse the existing circuit without recompilation.
    print(f"\n  ┌─ Use these parameters for the pruned circuit ──────────────")
    print(f"  │  Labels: 0 (dummy), 1..{n_pruned} (real)")
    print(f"  │  --pad-adjlist-to >= {n_pruned+2}  (e.g. 500 to reuse existing circuit)")
    print(f"  │  --adjlist-len >= {n_pruned+2}  (in compile_circuit.py)")
    print(f"  │  --pad-path-to <your_path_len>")
    print(f"  └────────────────────────────────────────────────────────────")


def write_dot(G: nx.DiGraph, path_info: dict, dot_path: str):
    path_nodes = path_info['path_nodes']
    path_edges = path_info['path_edges']
    initial    = path_info['initial']
    final      = path_info['final']

    def node_colour(n):
        if n == initial:    return COLOUR_INITIAL
        if n == final:      return COLOUR_FINAL
        if n in path_nodes: return COLOUR_PATH
        return COLOUR_DEFAULT

    lines = [
        'digraph CFG_pruned {',
        f'    graph [rankdir=TB fontname="monospace" bgcolor="{BG}" '
        f'label="Pruned CFG: {G.number_of_nodes()} nodes"];',
        '    node  [shape=box style=filled fontname="monospace" fontsize=9];',
        '    edge  [fontname="monospace" fontsize=8];',
    ]
    for n in sorted(G.nodes()):
        colour = node_colour(n)
        lines.append(f'    n{n} [label="{hex(n)}" '
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
    n_pruned  = G_pruned.number_of_nodes()
    e_pruned  = G_pruned.number_of_edges()
    n_removed = n_full - n_pruned
    e_removed = e_full - e_pruned

    print(f"\n  Mode            : {mode}")
    print(f"  Full CFG        : {n_full} nodes, {e_full} edges")
    print(f"  Pruned CFG      : {n_pruned} nodes, {e_pruned} edges")
    print(f"  Removed         : {n_removed} nodes ({n_removed/n_full*100:.0f}%), "
          f"{e_removed} edges ({e_removed/e_full*100:.0f}%)")

    missing = [hex(n) for n in path_info['path_nodes'] if n not in G_pruned]
    if missing:
        print(f"  [!] WARNING: {len(missing)} path nodes missing: {missing}")
    else:
        print(f"  Path integrity  : OK (all {len(path_info['path_nodes'])} path nodes preserved)")

    missing_edges = [(hex(u), hex(v)) for u, v in path_info['path_edges']
                     if not G_pruned.has_edge(u, v)]
    if missing_edges:
        print(f"  [!] WARNING: {len(missing_edges)} path edges missing from pruned CFG:")
        for u, v in missing_edges:
            print(f"       {u} -> {v}")
    else:
        print(f"  Edge integrity  : OK (all {len(path_info['path_edges'])} path edges preserved)")


# ── main pipeline ─────────────────────────────────────────────────────────────

def prune_dir(app_dir: str, mode: str = 'bidir'):
    adjlist_file = os.path.join(app_dir, 'adjlist')
    path_file    = os.path.join(app_dir, 'recorded_path')

    if not os.path.exists(adjlist_file):
        print(f"[!] {adjlist_file} not found — run extractor.py first"); return
    if not os.path.exists(path_file):
        print(f"[!] {path_file} not found — run extractor.py first"); return

    print(f"\n[prune] {app_dir}")
    G_full    = read_adjlist(adjlist_file)
    path_info = read_recorded_path(path_file)

    strategy = STRATEGIES[mode]
    G_pruned = strategy(G_full, path_info)

    print_stats(G_full, G_pruned, path_info, mode)

    write_adjlist(G_pruned, os.path.join(app_dir, 'adjlist_pruned'))
    write_numified_files(G_pruned, path_info, app_dir)
    write_dot(G_pruned, path_info, os.path.join(app_dir, 'cfg_pruned.dot'))
    render_svg(os.path.join(app_dir, 'cfg_pruned.dot'),
               os.path.join(app_dir, 'cfg_pruned.svg'))


# ── CLI ───────────────────────────────────────────────────────────────────────

def usage():
    print(f'Usage: {sys.argv[0]} -a <app_dir> | -d <apps_dir> [--mode path|forward|bidir]')
    print('  -a <path>                  Single application directory')
    print('  -d <path>                  Directory of multiple application folders')
    print('  --mode path|forward|bidir  Pruning strategy (default: bidir)')


if __name__ == '__main__':
    app_dir = apps_dir = None
    mode = 'bidir'

    try:
        opts, _ = getopt.getopt(sys.argv[1:], 'ha:d:', ['mode='])
    except getopt.GetoptError as e:
        print(e); usage(); sys.exit(2)

    for opt, arg in opts:
        if opt == '-h':       usage(); sys.exit()
        elif opt == '-a':     app_dir = arg.rstrip('/')
        elif opt == '-d':     apps_dir = arg.rstrip('/')
        elif opt == '--mode':
            if arg not in STRATEGIES:
                print(f"Unknown mode '{arg}'. Choose: {list(STRATEGIES)}"); sys.exit(2)
            mode = arg

    if app_dir:
        prune_dir(app_dir, mode)
    elif apps_dir:
        for entry in sorted(os.scandir(apps_dir), key=lambda e: e.name):
            if entry.is_dir():
                try:
                    prune_dir(entry.path, mode)
                except Exception as e:
                    print(f'[!] {entry.path}: {e}')
    else:
        print('No directory specified.'); usage(); sys.exit(2)