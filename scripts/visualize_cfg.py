"""
visualize_cfg.py  —  offline ZEKRA CFG + path renderer
=======================================================
Reads the files already written by extractor.py:

    <adjlist>          — hex-address adjacency list
    <recorded_path>    — execution path (jumpkinds + hex addresses)

Outputs (written to --out-dir, default: same directory as <adjlist>):
    cfg.dot          — always (open with xdot / Graphviz Online)
    cfg.svg          — if `dot` CLI is on PATH
    cfg.png          — full CFG with path overlay  (needs matplotlib)
    path.png         — path-only chain             (needs matplotlib)

Dependencies (all optional — DOT export works without any of them):
    matplotlib, pygraphviz
"""

import os, sys, getopt, subprocess, shutil
import networkx as nx

try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    HAS_MPL = True
except ImportError:
    HAS_MPL = False

try:
    import pygraphviz  # noqa
    HAS_PYGRAPHVIZ = True
except ImportError:
    HAS_PYGRAPHVIZ = False


# ─── file parsers ─────────────────────────────────────────────────────────────

def read_adjlist(path: str) -> nx.DiGraph:
    """
    Parse <app_dir>/adjlist into a NetworkX DiGraph.

    File format (written by extractor.get_adjlist):
        0x401234 0x401250 0x401280
        0x401250 0x401290
        0x401280
        ...
    First token on each line is the node; the rest are its successors.
    """
    G = nx.DiGraph()
    with open(path) as f:
        for line in f:
            tokens = line.split()
            if not tokens:
                continue
            src = int(tokens[0], 16)
            G.add_node(src)
            for dst_tok in tokens[1:]:
                dst = int(dst_tok, 16)
                G.add_edge(src, dst)
    return G


def read_recorded_path(path: str) -> dict:
    """
    Parse <app_dir>/recorded_path.

    File format (written by extractor.write_execution_path):
        initial_node=0x401234 final_node=0x401290
        call 0x401250 0x401280
        ret  0x401290
        jump 0x401300
        ...
    Returns:
        {'initial': int, 'final': int, 'sequence': [int, int, ...]}
    where sequence is [initial, dst0, dst1, ...].
    """
    with open(path) as f:
        lines = [l.rstrip() for l in f if l.strip()]

    header  = lines[0].split()
    initial = int(header[0].split('=')[1], 16)
    final   = int(header[1].split('=')[1], 16)

    sequence = [initial]
    for line in lines[1:]:
        parts = line.split()
        # parts[0]=jumpkind  parts[1]=dst  (parts[2]=ret for calls)
        sequence.append(int(parts[1], 16))

    return {'initial': initial, 'final': final, 'sequence': sequence}


# ─── colour helpers ───────────────────────────────────────────────────────────

COLOUR_INITIAL   = '#27ae60'   # green
COLOUR_FINAL     = '#e74c3c'   # red
COLOUR_PATH      = '#e67e22'   # orange
COLOUR_DEFAULT   = '#4a90d9'   # blue-grey
COLOUR_PATH_EDGE = '#8b0000'   # dark red
COLOUR_EDGE      = '#888888'   # grey
BG               = '#1a1a2e'


def node_colour(addr: int, path_info: dict) -> str:
    if addr == path_info['initial']:  return COLOUR_INITIAL
    if addr == path_info['final']:    return COLOUR_FINAL
    if addr in path_info['path_set']: return COLOUR_PATH
    return COLOUR_DEFAULT


# ─── DOT export ───────────────────────────────────────────────────────────────

def write_dot(G: nx.DiGraph, path_info: dict, dot_path: str):
    path_edges = set(zip(path_info['sequence'][:-1], path_info['sequence'][1:]))

    lines = [
        'digraph CFG {',
        f'    graph [rankdir=TB fontname="monospace" bgcolor="{BG}" '
        f'label="CFG: {G.number_of_nodes()} nodes"];',
        '    node  [shape=box style=filled fontname="monospace" fontsize=9];',
        '    edge  [fontname="monospace" fontsize=8];',
    ]
    for n in G.nodes():
        colour = node_colour(n, path_info)
        lines.append(f'    n{n} [label="{hex(n)}" fillcolor="{colour}" fontcolor="white"];')
    for u, v in G.edges():
        if (u, v) in path_edges:
            lines.append(f'    n{u} -> n{v} [color="{COLOUR_PATH_EDGE}" penwidth=2.5];')
        else:
            lines.append(f'    n{u} -> n{v} [color="{COLOUR_EDGE}" penwidth=0.8];')
    lines.append('}')

    with open(dot_path, 'w') as f:
        f.write('\n'.join(lines))
    print(f'[viz] DOT → {dot_path}')


def render_dot_svg(dot_path: str, svg_path: str):
    if shutil.which('dot') is None:
        print('[viz] `dot` not on PATH – skipping SVG  (apt install graphviz)')
        return
    try:
        subprocess.run(['dot', '-Tsvg', dot_path, '-o', svg_path],
                       check=True, capture_output=True)
        print(f'[viz] SVG → {svg_path}')
    except subprocess.CalledProcessError as e:
        print(f'[viz] dot failed: {e.stderr.decode()[:200]}')


# ─── matplotlib renders ───────────────────────────────────────────────────────

def _layout(G: nx.DiGraph) -> dict:
    if HAS_PYGRAPHVIZ:
        try:
            return nx.nx_agraph.graphviz_layout(G, prog='dot')
        except Exception:
            pass
    return nx.spring_layout(G, seed=42, k=2.0)


def render_full_cfg(G: nx.DiGraph, path_info: dict, out_path: str,
                    label_threshold: int = 150):
    if not HAS_MPL:
        print('[viz] matplotlib not installed – skipping PNG'); return

    path_edges = set(zip(path_info['sequence'][:-1], path_info['sequence'][1:]))
    n = G.number_of_nodes()

    node_colors = [node_colour(nd, path_info) for nd in G.nodes()]
    node_sizes  = [600 if nd in (path_info['initial'], path_info['final'])
                   else (400 if nd in path_info['path_set'] else 200)
                   for nd in G.nodes()]
    edge_colors = [COLOUR_PATH_EDGE if (u, v) in path_edges else COLOUR_EDGE
                   for u, v in G.edges()]
    edge_widths = [2.5 if (u, v) in path_edges else 0.8
                   for u, v in G.edges()]

    w = max(14, min(n * 0.25, 80))
    h = max(10, min(n * 0.20, 55))
    fig, ax = plt.subplots(figsize=(w, h))
    fig.patch.set_facecolor(BG); ax.set_facecolor(BG)

    pos = _layout(G)
    nx.draw_networkx_edges(G, pos, ax=ax,
                           edge_color=edge_colors, width=edge_widths,
                           arrows=True, arrowsize=10,
                           connectionstyle='arc3,rad=0.05',
                           min_source_margin=6, min_target_margin=6)
    nx.draw_networkx_nodes(G, pos, ax=ax,
                           node_color=node_colors, node_size=node_sizes,
                           edgecolors='white', linewidths=0.4)
    if n <= label_threshold:
        nx.draw_networkx_labels(G, pos, ax=ax,
                                labels={nd: hex(nd) for nd in G.nodes()},
                                font_size=6, font_color='white',
                                font_family='monospace')

    legend = [
        mpatches.Patch(color=COLOUR_INITIAL,  label='initial node'),
        mpatches.Patch(color=COLOUR_FINAL,    label='final node'),
        mpatches.Patch(color=COLOUR_PATH,     label='path node'),
        mpatches.Patch(color=COLOUR_DEFAULT,  label='other CFG node'),
        mpatches.Patch(color=COLOUR_PATH_EDGE, label='path edge'),
        mpatches.Patch(color=COLOUR_EDGE,     label='other edge'),
    ]
    ax.legend(handles=legend, loc='upper left',
              facecolor='#2c2c54', labelcolor='white', fontsize=8)
    ax.set_title(f'CFG ({n} nodes, {G.number_of_edges()} edges)  │  '
                 f'path: {len(path_info["sequence"])-1} transitions',
                 color='white', fontsize=10)
    ax.axis('off')
    plt.tight_layout()
    plt.savefig(out_path, dpi=150, bbox_inches='tight',
                facecolor=fig.get_facecolor())
    plt.close(fig)
    print(f'[viz] PNG → {out_path}')


def render_path_only(path_info: dict, out_path: str):
    if not HAS_MPL:
        return

    seq = path_info['sequence']
    G_p = nx.DiGraph()
    for i in range(len(seq) - 1):
        G_p.add_edge(seq[i], seq[i + 1])

    pos = _layout(G_p)
    n   = G_p.number_of_nodes()
    w   = max(10, min(n * 0.3, 60))
    h   = max(7,  min(n * 0.22, 40))

    fig, ax = plt.subplots(figsize=(w, h))
    fig.patch.set_facecolor(BG); ax.set_facecolor(BG)

    colors = [node_colour(nd, path_info) for nd in G_p.nodes()]
    nx.draw_networkx(G_p, pos, ax=ax,
                     node_color=colors, node_size=500,
                     edge_color=COLOUR_PATH_EDGE, width=2,
                     arrows=True, arrowsize=14,
                     labels={nd: hex(nd) for nd in G_p.nodes()},
                     font_size=7, font_color='white',
                     font_family='monospace')
    ax.set_title(f'Execution path  ({n} unique nodes, {len(seq)-1} transitions)',
                 color='white', fontsize=10)
    ax.axis('off')
    plt.tight_layout()
    plt.savefig(out_path, dpi=150, bbox_inches='tight',
                facecolor=fig.get_facecolor())
    plt.close(fig)
    print(f'[viz] path PNG → {out_path}')


# ─── main pipeline ────────────────────────────────────────────────────────────

def visualize_files(adjlist_file: str, path_file: str, out_dir: str = None,
                     no_render: bool = False):
    """
    Core entry point: render the CFG + path overlay from explicit file paths.

    adjlist_file — path to an `adjlist` file (hex-address adjacency list)
    path_file    — path to a `recorded_path` file (jumpkinds + hex addresses)
    out_dir      — where cfg.dot/svg/png + path.png are written;
                   defaults to the directory containing adjlist_file
    """
    if not os.path.exists(adjlist_file):
        print(f'[!] {adjlist_file} not found – run extractor.py first'); return
    if not os.path.exists(path_file):
        print(f'[!] {path_file} not found – run extractor.py first'); return

    if out_dir is None:
        out_dir = os.path.dirname(os.path.abspath(adjlist_file)) or '.'
    os.makedirs(out_dir, exist_ok=True)

    G         = read_adjlist(adjlist_file)
    path_info = read_recorded_path(path_file)
    path_info['path_set'] = set(path_info['sequence'])

    print(f'[viz] adjlist : {adjlist_file}')
    print(f'      path    : {path_file}')
    print(f'      CFG  : {G.number_of_nodes()} nodes, {G.number_of_edges()} edges')
    print(f'      Path : {len(path_info["sequence"])} addresses '
          f'({len(path_info["sequence"])-1} transitions)')
    print(f'      {hex(path_info["initial"])}  →  {hex(path_info["final"])}')

    dot_path = os.path.join(out_dir, 'cfg.dot')
    write_dot(G, path_info, dot_path)
    render_dot_svg(dot_path, os.path.join(out_dir, 'cfg.svg'))

    if not no_render:
        render_full_cfg(G, path_info, os.path.join(out_dir, 'cfg.png'))
        render_path_only(path_info, os.path.join(out_dir, 'path.png'))


def visualize_dir(app_dir: str, no_render: bool = False):
    """Batch-mode helper (used by -d): derive the standard adjlist/recorded_path
    file paths from an application directory, output written back into it."""
    adjlist_file = os.path.join(app_dir, 'adjlist')
    path_file    = os.path.join(app_dir, 'recorded_path')
    visualize_files(adjlist_file, path_file, out_dir=app_dir, no_render=no_render)


# ─── CLI ──────────────────────────────────────────────────────────────────────

def usage():
    print(f'Usage: {sys.argv[0]} -i <adjlist> -p <recorded_path> [-o <out_dir>] [--no-render]')
    print(f'       {sys.argv[0]} -d <apps_dir>  [--no-render]')
    print('  -i, --adjlist <path>        Path to an adjlist file')
    print('  -p, --recorded-path <path>  Path to a recorded_path file')
    print('  -o, --out-dir <path>        Where to write cfg.dot/svg/png + path.png')
    print('                              (default: same directory as <adjlist>)')
    print('  -d <path>                   Directory of multiple application folders')
    print('                              (batch mode; each must contain adjlist + recorded_path)')
    print('  --no-render                 Write DOT/SVG only; skip matplotlib PNG')


if __name__ == '__main__':
    adjlist_file = path_file = out_dir = apps_dir = None
    no_render = False

    try:
        opts, _ = getopt.getopt(sys.argv[1:], 'hi:p:o:d:',
                                 ['adjlist=', 'recorded-path=', 'out-dir=', 'no-render'])
    except getopt.GetoptError as e:
        print(e); usage(); sys.exit(2)

    for opt, arg in opts:
        if opt == '-h':                       usage(); sys.exit()
        elif opt in ('-i', '--adjlist'):       adjlist_file = arg
        elif opt in ('-p', '--recorded-path'): path_file = arg
        elif opt in ('-o', '--out-dir'):       out_dir = arg.rstrip('/')
        elif opt == '-d':                      apps_dir = arg.rstrip('/')
        elif opt == '--no-render':             no_render = True

    if adjlist_file or path_file:
        if not (adjlist_file and path_file):
            print('[!] -i/--adjlist and -p/--recorded-path must be given together.')
            usage(); sys.exit(2)
        visualize_files(adjlist_file, path_file, out_dir, no_render)
    elif apps_dir:
        for entry in sorted(os.scandir(apps_dir), key=lambda e: e.name):
            if entry.is_dir():
                print(f'\n{"─"*50}')
                try:
                    visualize_dir(entry.path, no_render)
                except Exception as e:
                    print(f'[!] {entry.path}: {e}')
    else:
        print('No directory specified.'); usage(); sys.exit(2)
