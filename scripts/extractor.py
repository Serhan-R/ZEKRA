#!/usr/bin/python3
#################################
## Author: Heini Bergsson Debes
#################################

import os, re, sys, getopt
import subprocess
import angr
import networkx as nx
import statistics
import logging
from angr.knowledge_plugins.cfg import CFGNode
from circuit_input_formatter import format_adjlist, encode_adjlist

def compile(c_filenames, out_file):
    cmd = ['gcc', '-o', out_file]
    cmd.extend(c_filenames)
    cmd.extend(['-Os', '-g0', '-lm', '-fno-optimize-sibling-calls'])
    print(' '.join(cmd))
    subprocess.run(cmd, check=True)

def get_cfg(proj, main_addr=None):
    """Extract CFG using CFGFast with better options for completeness."""
    cfg = proj.analyses.CFGFast(
        normalize=True, 
        show_progressbar=True, 
        resolve_indirect_jumps=True,
        force_complete_scan=True,  # Set to True if missing nodes
        start_at_entry=False if main_addr else True,
        function_starts=[main_addr] if main_addr else None,
    )
    return cfg

def _addr_in_binary(proj, addr):
    """Check if an address falls within any mapped region of the binary."""
    for obj in proj.loader.all_objects:
        if obj.min_addr <= addr <= obj.max_addr:
            return True
    return False

def _addr_is_executable(proj, addr):
    """Check if an address falls within an *executable* segment.
    Unlike _addr_in_binary, this excludes .got / .bss / .data even though
    they are within the binary's mapped range."""
    for obj in proj.loader.all_objects:
        if obj.min_addr <= addr <= obj.max_addr:
            for seg in obj.segments:
                if seg.vaddr <= addr < seg.vaddr + seg.memsize:
                    return seg.is_executable
            # Object has no segment info (e.g. angr's ExternObject for
            # SimProcedure stubs at 0x500000) — treat as executable
            return True
    return False

def get_execution_path(proj, cfg, main_addr):
    """
    Get execution path via symbolic execution.
    Fixed for angr 9.2.x compatibility.
    Fixed: Detects when execution leaves mapped binary memory (e.g., main() returning
    to CRT sentinel address 0x1) and terminates cleanly before recording the bogus transition.
    """
    program_args = ['./main']
    
    # Create initial state at main() address explicitly
    initial_state = proj.factory.entry_state(
        addr=main_addr,  # Start at main, not _start
        args=program_args,
        add_options={
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
        }
    )

    simgr = proj.factory.simgr(initial_state)
    transitions = []
    initial_node = main_addr  # Start at main
    final_node = 0
    end_state = None
    
    # Track the last valid address we were at (for setting final_node on clean exit)
    last_valid_addr = main_addr
    
    # Add timeout/step limit to prevent infinite loops
    MAX_STEPS = 10000
    step_count = 0
    
    try:
        while step_count < MAX_STEPS:
            step_count += 1
            simgr.step()
            
            # Check for completion conditions
            if len(simgr.active) == 0:
                if len(simgr.deadended) >= 1:
                    end_state = 'deadended (normal exit)'
                elif len(simgr.errored) >= 1:
                    # Check if the error is due to executing at an unmapped address
                    # This happens when main() returns to CRT sentinel (e.g., 0x1)
                    err = simgr.errored[0]
                    err_addr = getattr(err.state, 'addr', None) if hasattr(err, 'state') else None
                    if err_addr is not None and not _addr_in_binary(proj, err_addr):
                        end_state = f'clean exit (returned to unmapped address {hex(err_addr)})'
                        print(f"[+] Detected clean program exit: returned to {hex(err_addr)} (outside binary)")
                    else:
                        end_state = f'errored: {err.error}'
                else:
                    end_state = 'no active states'
                break
            
            if len(simgr.active) == 1:
                state = simgr.active[0]
                jumpkind = list(state.history.jumpkinds)[-1]
                
                # Get destination address - handle both concrete and symbolic
                target = state.history.jump_target
                if isinstance(target, int):
                    dst_addr = target
                elif state.solver.symbolic(target):
                    # First check if CFGFast already resolved this jump
                    src_addr = state.addr
                    cfg_nodes = cfg.model.get_all_nodes(src_addr)
                    resolved = False
                    if cfg_nodes:
                        successors = list(cfg.graph.successors(cfg_nodes[0]))
                        if len(successors) == 1:
                            # CFGFast resolved it to exactly one target, use that
                            dst_addr = successors[0].addr
                            resolved = True
                    if not resolved:
                        try:
                            dst_addr = state.solver.eval(target)
                        except:
                            end_state = 'symbolic jump target (unresolvable)'
                            break
                else:
                    dst_addr = state.solver.eval(target)
                
                # When main() returns, the CRT return address is typically 0x1 or
                # some other address outside the binary. Detect this and stop cleanly.
                if not _addr_is_executable(proj, dst_addr):
                    if jumpkind == 'Ijk_Ret':
                        end_state = f'clean exit (main returned to {hex(dst_addr)})'
                        print(f"[+] Detected clean program exit: main() returned to {hex(dst_addr)} (outside binary)")
                    else:
                        end_state = f'jumped to unmapped address {hex(dst_addr)} (jumpkind={jumpkind})'
                        print(f"[!] Execution jumped to unmapped address {hex(dst_addr)} via {jumpkind}")
                    # Do NOT record this transition - the destination is not a real node
                    # final_node stays as last_valid_addr
                    break
                
                if jumpkind == 'Ijk_Call':
                    ret_addr = state.callstack.ret_addr
                    transitions.append({
                        'jumpkind': 'call',
                        'dst': dst_addr,
                        'ret': ret_addr
                    })
                    last_valid_addr = dst_addr
                elif jumpkind == 'Ijk_Ret':
                    transitions.append({
                        'jumpkind': 'ret',
                        'dst': dst_addr,
                        'ret': None
                    })
                    last_valid_addr = dst_addr
                elif jumpkind == 'Ijk_Boring':
                    transitions.append({
                        'jumpkind': 'jump',
                        'dst': dst_addr,
                        'ret': None
                    })
                    last_valid_addr = dst_addr
                elif jumpkind == 'Ijk_Exit':
                    end_state = 'reached an exit'
                    break
                elif jumpkind == 'Ijk_Sys_syscall':
                    # System call - continue execution
                    last_valid_addr = dst_addr
                elif jumpkind == 'Ijk_NoHook':
                    # No hook - continue
                    last_valid_addr = dst_addr
                else:
                    print(f"[!] Encountered jumpkind = {jumpkind}, continuing...")
                    last_valid_addr = dst_addr
                    # Don't exit, just continue
                    
            elif len(simgr.active) > 1:
                # Multiple active states - pick the first one or merge
                print(f"[!] Multiple active states ({len(simgr.active)}), picking first")
                simgr.active = [simgr.active[0]]
                
        if step_count >= MAX_STEPS:
            end_state = f'reached max steps ({MAX_STEPS})'
            
    except Exception as e:
        print(f"[-] Exception during symbolic execution: {e}")
        import traceback
        traceback.print_exc()
        end_state = f'exception: {e}'

    # Add missing nodes and edges to CFG
    if transitions:
        state = initial_node
        for transition in transitions:
            dst = transition['dst']
            
            # Add return node for calls
            if transition['jumpkind'] == 'call' and transition['ret']:
                ret = transition['ret']
                if len(cfg.model.get_all_nodes(ret)) == 0:
                    node = CFGNode(ret, 0, cfg.model)
                    cfg.graph.add_node(node)
            
            # Add destination node if missing
            if len(cfg.model.get_all_nodes(dst)) == 0:
                node = CFGNode(dst, 0, cfg.model)
                cfg.graph.add_node(node)
            
            # Add edge
            src_nodes = cfg.model.get_all_nodes(state)
            dst_nodes = cfg.model.get_all_nodes(dst)
            if src_nodes and dst_nodes:
                edge = (src_nodes[0], dst_nodes[0])
                cfg.graph.add_edge(edge[0], edge[1])
            
            state = dst
        
        final_node = transitions[-1]['dst']
    else:
        final_node = initial_node
        print("[!] Warning: No transitions recorded")

    path = {
        'transitions': transitions,
        'initial_node': initial_node,
        'final_node': final_node
    }
    return end_state, cfg, path


# function code taken from https://stackoverflow.com/a/51827284
def find_repeated_sequences(s):
    match = re.findall(r'((\b.+?\b)(?:\s\2)+)', s)
    return [(m[1], int((len(m[0]) + 1) / (len(m[1]) + 1))) for m in match]

def generate_label_translator(labeled_cfg, raw_cfg, optimized_labeled_cfg):
    label_translator_optimized = {}
    for labeled_node, raw_node in zip(labeled_cfg.nodes(), raw_cfg.nodes()):
        optimized_label = None
        for j in optimized_labeled_cfg.nodes():
            if str(labeled_node) == optimized_labeled_cfg._node[j]['old_label']:
                optimized_label = j
                break
        if optimized_label is None:
            raise Exception(f'Could not find optimized label for node {labeled_node}')
        label_translator_optimized[hex(raw_node.block_id)] = optimized_label

    label_translator = {}
    for k in sorted(label_translator_optimized, key=label_translator_optimized.get, reverse=False):
        label_translator[k] = label_translator_optimized[k]

    return label_translator

def compress(path):
    transitions_merged_str = ''
    separator = '-'
    for transition in path['transitions']:
        transition_str = f"{transition['jumpkind']}{separator}{transition['dst']}{separator}{transition['ret']}"
        transitions_merged_str += f'{transition_str} '

    repetitions = find_repeated_sequences(transitions_merged_str)

    # compress the execution path (remove consecutively repeating BBL sequences, i.e., "loops")
    for repetition in repetitions:
        sequence = f'{repetition[0]} ' * int(repetition[1])
        transitions_merged_str = transitions_merged_str.replace(sequence, f'{repetition[0]} ')
    
    # recreate the compressed execution path
    tmp = []
    if transitions_merged_str.strip():
        for transition in transitions_merged_str.strip().split(' '):
            parts = transition.split(separator)
            if len(parts) >= 3:
                jumpkind, dst, ret = parts[0], parts[1], parts[2]
                tmp.append({
                    'jumpkind': jumpkind,
                    'dst': dst,
                    'ret': ret
                })
    if tmp:
        path['final_node'] = tmp[-1]['dst']
    sequence_lengths = []
    sequence_repetitions = []
    sum_repetitions_length = 0
    number_of_repetitions = len(repetitions)
    
    for repetition in repetitions:
        sequence_length = len(repetition[0].split(' '))
        sequence_lengths.append(sequence_length)
        sequence_repetitions.append(repetition[1])
        sum_repetitions_length += sequence_length * repetition[1]

    execution_path_length_pre_compression = len(path['transitions'])
    execution_path_length_post_compression = len(tmp)

    mean_sequence_lengths = 0
    mean_sequence_repetitions = 0
    stdev_sequence_lengths = 0
    stdev_sequence_repetitions = 0
    
    if number_of_repetitions > 0:
        mean_sequence_lengths = sum(sequence_lengths) / number_of_repetitions
        mean_sequence_repetitions = sum(sequence_repetitions) / number_of_repetitions
        stdev_sequence_lengths = statistics.pstdev(sequence_lengths)
        stdev_sequence_repetitions = statistics.pstdev(sequence_repetitions)

    stats = {
        'execution_path_length_pre_compression': execution_path_length_pre_compression,
        'repetitions': repetitions,
        'number_of_repetitions': number_of_repetitions,
        'mean_sequence_lengths': mean_sequence_lengths,
        'stdev_sequence_lengths': stdev_sequence_lengths,
        'mean_sequence_repetitions': mean_sequence_repetitions,
        'stdev_sequence_repetitions': stdev_sequence_repetitions,
        'execution_path_length_post_compression': execution_path_length_post_compression
    }
    path['transitions'] = tmp
    return path, stats

def hexify_labels(path):
    path['initial_node'] = hex(path['initial_node'])
    path['final_node'] = hex(path['final_node'])
    
    for i in range(len(path['transitions'])):
        path['transitions'][i]['dst'] = hex(path['transitions'][i]['dst'])
        if path['transitions'][i]['jumpkind'] == 'call' and path['transitions'][i]['ret']:
            path['transitions'][i]['ret'] = hex(path['transitions'][i]['ret'])
    return path

def numify_labels(path, node_label_translator):
    # Check if initial_node exists in translator
    if path['initial_node'] not in node_label_translator:
        print(f"[!] Warning: initial_node {path['initial_node']} not in translator")
        print(f"    Available keys (first 10): {list(node_label_translator.keys())[:10]}")
        return None
        
    path['initial_node'] = node_label_translator[path['initial_node']]
    
    if path['final_node'] not in node_label_translator:
        print(f"[!] Warning: final_node {path['final_node']} not in translator")
        return None
        
    path['final_node'] = node_label_translator[path['final_node']]
    
    for i in range(len(path['transitions'])):
        dst = path['transitions'][i]['dst']
        if dst not in node_label_translator:
            print(f"[!] Warning: destination {dst} not in translator")
            return None
        path['transitions'][i]['dst'] = node_label_translator[dst]
        
        if path['transitions'][i]['jumpkind'] == 'call':
            ret = path['transitions'][i]['ret']
            if ret and ret not in node_label_translator:
                print(f"[!] Warning: return address {ret} not in translator")
                return None
            if ret:
                path['transitions'][i]['ret'] = node_label_translator[ret]
    return path

def write_execution_path(filename, path):
    with open(filename, 'w') as out:
        out.write(f"initial_node={path['initial_node']} final_node={path['final_node']}\n")
        for transition in path['transitions']:
            if transition['jumpkind'] == 'call':
                out.write(f"{transition['jumpkind']} {transition['dst']} {transition['ret']}\n")
            else:
                out.write(f"{transition['jumpkind']} {transition['dst']}\n")

def get_addr(label, cfg):
    addr = None
    for node in list(cfg.graph.nodes()):
        if str(node) == label:
            addr = node.addr
            break
    return addr

def write_adjlist(filename, adjlist):
    with open(filename, 'w') as out:
        for node in adjlist:
            out.write(node + '\n')

def valid_execution_path(execution_path, adjlist):
    """Checks if the execution path can traverse in the forward direction."""
    state = execution_path['initial_node']
    
    for transition in execution_path['transitions']:
        if str(state) not in adjlist:
            print(f"[!] State {state} not in adjacency list")
            return str(state) == str(execution_path['final_node'])
            
        legal_destinations = adjlist[str(state)]
        if transition['dst'] in legal_destinations:
            state = transition['dst']
        else:
            print(f"[!] {transition['dst']} not a neighbor of {state}. Valid neighbors: {legal_destinations}")
            return False
            
    return str(state) == str(execution_path['final_node'])

def get_adjlist(cfg):
    adjlist_labels = list(nx.generate_adjlist(cfg.graph))
    adjlist = []
    for node in adjlist_labels:
        addrs = ''
        nodes = node.split('>')
        for _node in nodes:
            if _node == '':
                continue
            _node = str(_node).lstrip() + '>'
            addr = get_addr(_node, cfg)
            if addr is not None:
                addrs += f'{hex(addr)} '
        adjlist.append(addrs.rstrip())
    return adjlist

def find_c_file(foldername):
    c_files = []
    for file in os.listdir(os.fsencode(foldername)):
        filename = os.fsdecode(file)
        if not filename.endswith('.c'):
            continue
        c_files.append(foldername + '/' + filename)
    return c_files

def run(application_foldername):
    output = ''
    c_filenames = find_c_file(application_foldername)
    
    if not c_filenames:
        return f"\n{application_foldername}\nERROR: No .c files found\n"
    
    out_file = application_foldername + '/main'

    try:
        compile(c_filenames, out_file)
    except subprocess.CalledProcessError as e:
        return f"\n{application_foldername}\nERROR: Compilation failed: {e}\n"

    # Load the compiled application
    proj = angr.Project(out_file, load_options={'auto_load_libs': False})
    
    # Find main symbol
    main_sym = proj.loader.find_symbol('main')
    if main_sym is None:
        return f"\n{application_foldername}\nERROR: Could not find 'main' symbol\n"
    
    main_addr = main_sym.rebased_addr
    print(f"[+] Found main() at {hex(main_addr)}")

    # Extract CFG starting from main
    cfg = get_cfg(proj, main_addr)
    
    # Get example execution path
    end_state, cfg, path = get_execution_path(proj, cfg, main_addr)
    
    if not path['transitions']:
        return f"\n{application_foldername}\nERROR: No execution path extracted (end_state: {end_state})\n"
 
    # Hexify the labels
    path = hexify_labels(path)

    labeled_cfg = nx.convert_node_labels_to_integers(cfg.graph, ordering='default')
    labeled_cfg_adjlist = list(nx.generate_adjlist(labeled_cfg))
    labeled_numified_adjlist = format_adjlist(labeled_cfg_adjlist)

    optimized_cfg = nx.DiGraph()
    for node, neighbors in labeled_numified_adjlist.items():
        optimized_cfg.add_node(node)
        for neighbor in neighbors:
            optimized_cfg.add_edge(node, neighbor)

    optimized_labeled_cfg = nx.convert_node_labels_to_integers(
        optimized_cfg, 
        ordering='default', 
        label_attribute='old_label'
    )
    
    try:
        node_label_translator = generate_label_translator(labeled_cfg, cfg.graph, optimized_labeled_cfg)
    except Exception as e:
        return f"\n{application_foldername}\nERROR: Failed to generate label translator: {e}\n"

    with open(application_foldername + '/translator', 'w') as out:
        for raw_address in node_label_translator:
            out.write(f'{raw_address}\n')

    output += f'\n{application_foldername}\n'
    output += f'Min addr: {hex(proj.loader.min_addr)}\n'
    output += f'Max addr: {hex(proj.loader.max_addr)} (bitwidth={len(format(proj.loader.max_addr, "0b"))})\n'
    output += f'CFG has {len(cfg.graph.nodes())} nodes and {len(cfg.graph.edges())} edges\n'
    
    numified_adjlist = list(nx.generate_adjlist(optimized_labeled_cfg))
    write_adjlist(application_foldername + '/numified_adjlist', numified_adjlist)
    write_adjlist(application_foldername + '/adjlist', get_adjlist(cfg))

    numified_adjlist = format_adjlist(numified_adjlist)
    max_neighbors_set = max(numified_adjlist.values(), key=len) if numified_adjlist else []
    adjlist_encoded = encode_adjlist(numified_adjlist)
    levels_required = len(max([list(levels) for node, levels in adjlist_encoded], key=len)) if adjlist_encoded else 0
    
    output += f'Adjacency list max_neighbors: {len(max_neighbors_set)} {max_neighbors_set}\n'
    output += f'Bucket-rems pairs (levels) required: {levels_required}\n'
    
    # Write raw execution path
    raw_path, raw_path_stats = compress(path.copy())
    write_execution_path(f'{application_foldername}/recorded_path', raw_path)
    
    # Numify the execution path
    path_numified = numify_labels(path.copy(), node_label_translator)
    
    if path_numified is None:
        return output + "ERROR: Failed to numify execution path (missing labels)\n"
    
    path_numified, stats = compress(path_numified)
    
    # Write numified execution path
    write_execution_path(f'{application_foldername}/numified_path', path_numified)
    
    # Write stats
    output += f'Execution path ended because: {end_state}\n'
    output += f'Execution path length pre compression: {stats["execution_path_length_pre_compression"]}\n'
    output += f'Number of consecutively repeated sequences: {stats["number_of_repetitions"]}\n'
    output += f'Average (mean) length of sequences: {stats["mean_sequence_lengths"]:.2f} (std={stats["stdev_sequence_lengths"]:.2f})\n'
    output += f'Average (mean) number of sequence repetitions: {stats["mean_sequence_repetitions"]:.2f} (std={stats["stdev_sequence_repetitions"]:.2f})\n'
    output += f'Execution path length post compression: {stats["execution_path_length_post_compression"]}\n'
    
    # Compute max stack depth
    max_stack_depth = 0
    cur_stack_depth = 0
    for transition in path_numified['transitions']:
        if transition['jumpkind'] == 'call':
            cur_stack_depth += 1
            max_stack_depth = max(max_stack_depth, cur_stack_depth)
        elif transition['jumpkind'] == 'ret':
            cur_stack_depth -= 1
    output += f'Max stack depth: {max_stack_depth}\n'
    
    # Validate execution path
    is_valid = valid_execution_path(path_numified, numified_adjlist)
    output += f'Execution path is valid according to adjlist: {is_valid}\n'
    
    return output

def write_stats(message, foldername=None, mode='w'):
    filename = 'stats.log'
    if foldername:
        filename = foldername + '/' + filename
    with open(filename, mode) as out:
        out.write(message + '\n')

def main(applications_dir, target_application_dir, exclude_dirs):
    merged_output = ''
    
    if target_application_dir is not None:
        output = run(target_application_dir)
        write_stats(output, target_application_dir)
        merged_output += output
    else:
        subfolders = [f.path for f in os.scandir(applications_dir) if f.is_dir()]
        if len(subfolders) == 0:
            print(f'No applications found in: {applications_dir}')
            exit(2)
            
        for foldername in subfolders:
            tmp = foldername
            if len(tmp.split('/')) > 0:
                tmp = tmp.split('/')[-1]
            if tmp in exclude_dirs:
                continue
            
            print(f"\n{'='*60}")
            print(f"Processing: {foldername}")
            print('='*60)
            
            try:
                output = run(foldername)
                write_stats(output, foldername)
                merged_output += output
            except Exception as e:
                error_msg = f"\n{foldername}\nERROR: {e}\n"
                print(error_msg)
                import traceback
                traceback.print_exc()
                merged_output += error_msg
                
    print(merged_output)

def usage():
    print(f'Usage: {sys.argv[0]} [options]')
    print('Options:')
    print('  -h               This help message')
    print('  -v               Verbose output')
    print('  -d <path/to/dir> Directory containing target applications')
    print('  -a <path>        Path to specific target application')
    print('  -e <name1,name2> Comma separated list of folders to exclude')

if __name__ == '__main__':
    applications_dir = './embench-iot-applications'
    target_application_dir = None
    exclude_dirs = []
    
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'hvd:a:e:')
    except getopt.GetoptError as err:
        print(err)
        usage()
        sys.exit(2)
        
    for opt, arg in opts:
        if opt == '-h':
            usage()
            sys.exit()
        elif opt == '-v':
            logging.getLogger('angr').setLevel('DEBUG')
        elif opt == '-d':
            if arg.endswith('/'):
                arg = arg[:-1]
            applications_dir = arg
        elif opt == '-a':
            if arg.endswith('/'):
                arg = arg[:-1]
            target_application_dir = arg
        elif opt == '-e':
            exclude_dirs = [foldername for foldername in arg.split(',')]
            
    main(applications_dir, target_application_dir, exclude_dirs)