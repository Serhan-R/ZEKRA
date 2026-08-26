#!/usr/bin/python3
#################################
## roi_detector.py
#################################
# Detects candidate function-level "region(s) of interest" (ROI) in an
# embench-style app, for region_prune.py's `--mode region --function <names>`
# (and roi_extractor.py, which wraps this module + region_prune.prune_dir()).
#
# Detection order:
#   1. LLM pass -- send the app's C source to an LLM and ask it to name the
#      core algorithmic function(s), as opposed to boilerplate/I/O/harness
#      code. Provider is 'anthropic' (anthropic SDK + ANTHROPIC_API_KEY) or
#      'gemini' (stdlib urllib against the Generative Language REST API +
#      GEMINI_API_KEY/GOOGLE_API_KEY, model resolved live via ListModels).
#      Selected via provider=/--provider/ROI_DETECTOR_PROVIDER (default
#      'anthropic'); both providers share the same prompt template.
#   2. Heuristic fallback (LLM unavailable, no key, network/parse error):
#      rank defined functions by "branch density" -- CFG nodes (from
#      extractor.py's adjlist) inside the function's address range, over its
#      byte size (nm -S) -- a proxy for "tight, branchy, algorithmic" code.
#
# Both paths validate their proposed name(s) against the binary's real
# symbol table (region_prune.lookup_function_ranges) before returning, so
# results are always safe to hand to region_prune.py's --function flag.
#
# Read-only with respect to app_dir: only reads adjlist / C sources / the
# compiled "main" binary. Never writes adjlist_pruned/etc -- that's
# roi_extractor.py's job.

import os, sys, glob, json, re, getopt, subprocess, bisect, time
import urllib.request, urllib.error

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import region_prune  # read-only reuse: lookup_function_ranges(), read_adjlist()


DEFAULT_PROVIDER = os.environ.get('ROI_DETECTOR_PROVIDER', 'gemini')
DEFAULT_ANTHROPIC_MODEL = os.environ.get('ROI_DETECTOR_MODEL', 'claude-sonnet-4-6')
# Last-resort guess, only ever used if live Gemini model discovery itself
# fails (e.g. no network) -- see resolve_gemini_model() / gemini_detect().
DEFAULT_GEMINI_MODEL_FALLBACK = 'gemini-1.5-flash-latest'
GEMINI_API_BASE = 'https://generativelanguage.googleapis.com/v1beta'
MAX_SOURCE_CHARS = 60000  # keep the LLM prompt within a reasonable size

# The whole-program entry point is not a "sub-region" — never propose it.
EXCLUDE_FUNCTIONS = {'main'}

# Cache file written into <app_dir> after a successful detect_roi() call, so
# that separate invocations against the same app_dir (e.g. running
# roi_detector.py once to preview, then roi_extractor.py/roi_circuit_check.py
# to actually act) agree on the same answer instead of each making its own
# fresh LLM call and risking a different sample. See detect_roi() below.
ROI_CACHE_FILENAME = '.roi_detect_cache.json'


# ─────────────────────────── source collection ─────────────────────────────

def find_c_files(app_dir):
    """
    All *.c files directly inside app_dir. Deliberately re-implemented here
    (instead of importing extractor.find_c_file) because extractor.py does
    `import angr` at module scope, which would make this module require angr
    just to list source files. This is a 1-line glob, not a re-implementation
    of any of extractor.py's actual CFG/symbolic-execution logic.
    """
    return sorted(glob.glob(os.path.join(app_dir, '*.c')))


def read_source(app_dir):
    chunks = []
    for path in find_c_files(app_dir):
        try:
            with open(path, 'r', errors='replace') as f:
                chunks.append('// ----- %s -----\n%s' % (os.path.basename(path), f.read()))
        except OSError:
            continue
    source = '\n\n'.join(chunks)
    if len(source) > MAX_SOURCE_CHARS:
        source = source[:MAX_SOURCE_CHARS] + '\n// ... [truncated] ...\n'
    return source


# ─────────────────────────── symbol helpers ─────────────────────────────────

def list_defined_functions(binary_path):
    """All defined (T/W), non-zero-size functions, as (addr, size, name)."""
    if not os.path.exists(binary_path):
        return []
    result = subprocess.run(['nm', '--defined-only', '-S', binary_path],
                             capture_output=True, text=True)
    funcs = []
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[2].upper() in ('T', 'W'):
            try:
                addr = int(parts[0], 16)
                size = int(parts[1], 16)
                name = parts[3]
                if size > 0:
                    funcs.append((addr, size, name))
            except ValueError:
                continue
    return funcs


def validate_function_names(app_dir, names):
    """Keep only names that resolve to a real defined function in <app_dir>/main,
    preserving the caller's ordering and de-duplicating."""
    if not names:
        return []
    binary_path = os.path.join(app_dir, 'main')
    try:
        found = region_prune.lookup_function_ranges(binary_path, names, app_dir=app_dir)
    except FileNotFoundError:
        return []
    found_names = {name for _, _, name in found}
    seen, ordered = set(), []
    for n in names:
        if n in found_names and n not in seen:
            ordered.append(n)
            seen.add(n)
    return ordered


# ─────────────────────── execution-trace visibility ─────────────────────────

def get_trace_addresses(app_dir):
    """Return a sorted list of every instruction address mentioned in
    <app_dir>/recorded_path (hex tokens starting with '0x'). Used to detect
    whether a function's address range was actually traversed during the
    recorded run -- functions not represented here were inlined away by the
    compiler and cannot serve as ROI anchors."""
    path_file = os.path.join(app_dir, 'recorded_path')
    addrs = set()
    if not os.path.exists(path_file):
        return []
    with open(path_file) as f:
        for line in f:
            for tok in line.split():
                if tok.startswith('0x'):
                    try:
                        addrs.add(int(tok, 16))
                    except ValueError:
                        pass
    return sorted(addrs)


def _range_intersects_trace(lo, hi, sorted_trace):
    """True if any address in sorted_trace falls in [lo, hi). O(log n)."""
    idx = bisect.bisect_left(sorted_trace, lo)
    return idx < len(sorted_trace) and sorted_trace[idx] < hi


def filter_trace_visible(app_dir, binary_path, names):
    """Filter `names` to those whose address range (PIE-corrected) contains at
    least one address from the recorded execution path. Preserves ordering.

    Degrades gracefully: if recorded_path is absent, or if *all* candidates
    fail the filter (e.g. a truly fully-inlined function), returns the
    original `names` unchanged so that prune_dir() can surface the real error
    rather than silently returning an empty list here."""
    sorted_trace = get_trace_addresses(app_dir)
    if not sorted_trace:
        return names  # no trace data -- can't filter, pass through
    try:
        ranges = region_prune.lookup_function_ranges(binary_path, names, app_dir=app_dir)
    except FileNotFoundError:
        return names
    visible = {name for lo, hi, name in ranges if _range_intersects_trace(lo, hi, sorted_trace)}
    filtered = [n for n in names if n in visible]
    if not filtered:
        print('[roi_detector] Warning: %s not found in recorded_path (likely inlined '
              'at -Os) -- passing through unfiltered; prune_dir() will report the '
              'real failure.' % ', '.join(names))
        return names
    return filtered


def get_trace_visible_function_names(app_dir):
    """Names of every non-excluded defined function whose address range
    intersects the recorded execution path. Returns [] if the recorded_path
    is absent or the binary is missing. Used to inform the LLM which
    functions it may safely anchor the ROI on."""
    binary_path = os.path.join(app_dir, 'main')
    sorted_trace = get_trace_addresses(app_dir)
    if not sorted_trace:
        return []
    funcs = list_defined_functions(binary_path)
    if not funcs:
        return []
    delta = region_prune.detect_rebase_delta(app_dir, binary_path)
    return [name for addr, size, name in funcs
            if name not in EXCLUDE_FUNCTIONS
            and _range_intersects_trace(addr + delta, addr + size + delta, sorted_trace)]


# ──────────────────────── address-space reconciliation ───────────────────────
# `nm` reports a binary's linked (file) addresses, but angr/CLE rebases PIE
# binaries at runtime, so nm's addresses and the CFG's (adjlist/translator)
# addresses can differ by a constant delta. region_prune.py calibrates and
# applies this delta itself (detect_rebase_delta() /
# lookup_function_ranges(..., app_dir=...)) -- this module just calls into
# that directly (see heuristic_detect() below and validate_function_names()
# above) instead of keeping a second copy of the same logic.


# ─────────────────────────── heuristic fallback ──────────────────────────────

def heuristic_detect(app_dir, top_n=1):
    """
    Ranks defined functions by branch density = (# CFG nodes inside the
    function's address range) / size_bytes, using the extracted adjlist and
    `nm -S` (corrected for the PIE rebase delta -- see "address-space
    reconciliation" above). Higher density approximates "tight, branchy,
    algorithmic" code, a proxy for the ROI when no LLM judgement is
    available. Functions with >=2 recorded CFG nodes are preferred (1 node
    is a single straight-line block -- no real branching, just a tiny-
    denominator artifact), then functions with >0 nodes; both filters
    degrade to "all" rather than ever hard-failing.
    """
    binary_path = os.path.join(app_dir, 'main')
    funcs = [(a, s, n) for a, s, n in list_defined_functions(binary_path)
              if n not in EXCLUDE_FUNCTIONS]
    if not funcs:
        return []

    adjlist_path = os.path.join(app_dir, 'adjlist')
    node_addrs = []
    if os.path.exists(adjlist_path):
        G = region_prune.read_adjlist(adjlist_path)
        node_addrs = list(G.nodes())

    delta = region_prune.detect_rebase_delta(app_dir, binary_path)
    sorted_trace = get_trace_addresses(app_dir)

    scored = []
    for addr, size, name in funcs:
        lo, hi = addr + delta, addr + size + delta
        node_count = sum(1 for a in node_addrs if lo <= a < hi)
        density = node_count / size if size else 0
        in_trace = bool(sorted_trace and _range_intersects_trace(lo, hi, sorted_trace))
        scored.append((density, node_count, in_trace, name))

    scored.sort(key=lambda t: (t[0], t[1]), reverse=True)
    # Prefer trace-visible functions (not inlined) first, then fall back to
    # CFG-based tiers.  Each tier degrades to the next rather than hard-failing.
    branchy_trace = [s for s in scored if s[1] >= 2 and s[2]]
    branchy       = [s for s in scored if s[1] >= 2]
    active_trace  = [s for s in scored if s[1] >  0 and s[2]]
    with_activity = [s for s in scored if s[1] >  0]
    ranked = branchy_trace or branchy or active_trace or with_activity or scored
    return [name for _, _, _, name in ranked[:top_n]]


# ─────────────────────────── LLM detection ───────────────────────────────────

LLM_PROMPT_TEMPLATE = '''You are analyzing embedded-systems C source code to choose a \
"region of interest" (ROI) for a control-flow attestation system. The system proves, in \
zero-knowledge, that the program's actual execution path is consistent with a committed \
control-flow graph. Proving the *entire* program is expensive, so we want to attest only \
a sub-region: the function (or small number of functions) that contains the core, \
algorithmically/security-critical logic of the program -- as opposed to boilerplate, I/O, \
benchmark-harness/setup code, or trivial wrappers.

Pick {top_n} function name(s) (fewer is fine if the source clearly has a single hot \
function). Use the exact function names as they appear in the C source. Respond with ONLY \
a JSON object, no other text, in exactly this form:
{{"functions": ["function_name", ...], "reasoning": "one sentence"}}
{trace_hint}
Source code:
{source}
'''

_TRACE_HINT_TEMPLATE = (
    '\nIMPORTANT: You MUST choose only from the following functions. These are the '
    'only functions confirmed present in the recorded execution trace -- all others '
    'were inlined away by the compiler (-Os) and cannot anchor the circuit:\n'
    '  {names}\n'
)


def parse_llm_response(text):
    """Extract the JSON object (tolerating stray text/markdown fences around it)
    and return its 'functions' list, or None on any failure to parse."""
    match = re.search(r'\{.*\}', text, re.DOTALL)
    if not match:
        return None
    try:
        data = json.loads(match.group(0))
    except json.JSONDecodeError:
        return None
    names = data.get('functions')
    if not isinstance(names, list) or not names:
        return None
    return [str(n).strip() for n in names if str(n).strip()]


def anthropic_detect(app_dir, top_n=1, model=None):
    """
    Returns a list of function names chosen by an LLM (Anthropic API)
    reading the app's C source, or None if the LLM path could not be used
    at all (missing SDK, missing API key, no source, network/API error, or
    an unparsable response). Callers should treat None as "fall back to
    heuristic_detect()".
    """
    try:
        import anthropic
    except ImportError:
        print('[roi_detector] anthropic SDK not installed -- skipping LLM detection.')
        return None

    api_key = os.environ.get('ANTHROPIC_API_KEY')
    if not api_key:
        print('[roi_detector] ANTHROPIC_API_KEY not set -- skipping LLM detection.')
        return None

    source = read_source(app_dir)
    if not source.strip():
        print('[roi_detector] No C source found in %s -- skipping LLM detection.' % app_dir)
        return None

    trace_fns = get_trace_visible_function_names(app_dir)
    trace_hint = _TRACE_HINT_TEMPLATE.format(names=', '.join(trace_fns)) if trace_fns else ''
    prompt = LLM_PROMPT_TEMPLATE.format(top_n=top_n, source=source, trace_hint=trace_hint)
    model = model or DEFAULT_ANTHROPIC_MODEL

    try:
        client = anthropic.Anthropic(api_key=api_key)
        response = client.messages.create(
            model=model,
            max_tokens=1024,
            temperature=0,  # ROI selection should be reproducible, not sampled
            messages=[{'role': 'user', 'content': prompt}],
        )
        text = ''.join(
            block.text for block in response.content
            if getattr(block, 'type', None) == 'text'
        )
    except Exception as exc:
        print('[roi_detector] LLM call failed (%s) -- falling back to heuristic.' % exc)
        return None

    names = parse_llm_response(text)
    if not names:
        print('[roi_detector] Could not parse LLM response -- falling back to heuristic.')
        return None
    return names


# ─────────────────────────── Gemini provider ──────────────────────────────
# Implemented against Google's REST API directly (stdlib urllib, no SDK
# dependency). The API key is sent via the `x-goog-api-key` header rather
# than a `?key=...` query param, to keep it out of logged URLs. Model id is
# resolved live via ListModels (preferring a "flash" model) unless the
# caller passes one explicitly -- hardcoded ids go stale as models get
# retired. DEFAULT_GEMINI_MODEL_FALLBACK is used only if live discovery
# itself fails (e.g. no network).

def _gemini_list_models(api_key):
    """Raises on any transport/HTTP error; callers decide how to degrade."""
    url = '%s/models?pageSize=100' % GEMINI_API_BASE
    req = urllib.request.Request(url, headers={'x-goog-api-key': api_key})
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read().decode('utf-8'))
    return data.get('models', [])


def resolve_gemini_model(api_key, preferred=None):
    """
    Returns `preferred` unmodified if given (an explicit caller choice is
    trusted as-is and never second-guessed here). Otherwise queries
    ListModels live and returns the first model name that supports
    generateContent, preferring one with "flash" in its name. Returns None
    if discovery isn't possible (e.g. network/auth error) -- callers should
    fall back further (see DEFAULT_GEMINI_MODEL_FALLBACK).
    """
    if preferred:
        return preferred
    try:
        models = _gemini_list_models(api_key)
    except Exception:
        return None
    candidates = [m for m in models
                  if 'generateContent' in m.get('supportedGenerationMethods', [])]
    if not candidates:
        return None
    flash = [m for m in candidates if 'flash' in m.get('name', '').lower()]
    chosen = (flash or candidates)[0]
    name = chosen.get('name', '')
    return name.rsplit('/', 1)[-1] if name else None


def _gemini_generate_content(api_key, model, prompt):
    """One generateContent call; raises urllib.error.HTTPError / URLError on
    any transport/HTTP failure so callers can distinguish a stale model id
    (HTTPError code 404, worth retrying with a different model) from other
    failures (not worth retrying)."""
    url = '%s/models/%s:generateContent' % (GEMINI_API_BASE, model)
    # temperature=0: ROI selection should be reproducible, not sampled --
    # the same source should yield the same chosen function(s) every time.
    body = json.dumps({
        'contents': [{'parts': [{'text': prompt}]}],
        'generationConfig': {'temperature': 0},
    }).encode('utf-8')
    req = urllib.request.Request(
        url, data=body, method='POST',
        headers={'x-goog-api-key': api_key, 'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=60) as resp:
        data = json.loads(resp.read().decode('utf-8'))
    candidates = data.get('candidates') or []
    if not candidates:
        return ''
    parts = candidates[0].get('content', {}).get('parts', [])
    return ''.join(p.get('text', '') for p in parts)


def _gemini_call_with_retry(api_key, model, prompt, max_retries=2, base_wait_s=65):
    """Wraps _gemini_generate_content with exponential-backoff retry on HTTP 429.
    base_wait_s=65 is just over one full minute, safe for a 1 RPM free-tier limit.
    Retries: 65 s, then 130 s.  Raises the last HTTPError if still failing after
    max_retries, so the caller can decide whether to fall back to heuristic."""
    for attempt in range(max_retries + 1):
        try:
            return _gemini_generate_content(api_key, model, prompt)
        except urllib.error.HTTPError as exc:
            if exc.code == 429 and attempt < max_retries:
                wait_s = base_wait_s * (2 ** attempt)   # 65 s, then 130 s
                print('[roi_detector] HTTP 429 rate limit -- waiting %ds before retry '
                      '(%d/%d)...' % (wait_s, attempt + 1, max_retries))
                time.sleep(wait_s)
                continue
            raise   # non-429 or retries exhausted -- let gemini_detect handle it


def _gemini_model_attempts(api_key, preferred):
    """Yields model ids to try, lazily: `preferred` first (if given), then a
    live-discovered model (only computed if actually needed -- i.e. if the
    first attempt fails with a stale-model error), then the hardcoded
    last-resort fallback if even discovery failed. Generator laziness here
    means ListModels is never called at all on the common path where the
    first attempt simply succeeds."""
    if preferred:
        yield preferred
    discovered = resolve_gemini_model(api_key, preferred=None)
    if discovered and discovered != preferred:
        yield discovered
    if not preferred and not discovered:
        yield DEFAULT_GEMINI_MODEL_FALLBACK


def gemini_detect(app_dir, top_n=1, model=None):
    """
    Returns a list of function names chosen by an LLM (Gemini API) reading
    the app's C source, or None if the Gemini path could not be used at all
    (missing API key, no source, network/API error, or an unparsable
    response). Callers should treat None as "fall back to
    heuristic_detect()" -- same contract as anthropic_detect().
    """
    api_key = os.environ.get('GEMINI_API_KEY') or os.environ.get('GOOGLE_API_KEY')
    if not api_key:
        print('[roi_detector] GEMINI_API_KEY (or GOOGLE_API_KEY) not set '
              '-- skipping Gemini detection.')
        return None

    source = read_source(app_dir)
    if not source.strip():
        print('[roi_detector] No C source found in %s -- skipping Gemini detection.' % app_dir)
        return None

    trace_fns = get_trace_visible_function_names(app_dir)
    trace_hint = _TRACE_HINT_TEMPLATE.format(names=', '.join(trace_fns)) if trace_fns else ''
    prompt = LLM_PROMPT_TEMPLATE.format(top_n=top_n, source=source, trace_hint=trace_hint)
    preferred_model = model or os.environ.get('ROI_DETECTOR_GEMINI_MODEL')

    text, tried = None, []
    for attempt_model in _gemini_model_attempts(api_key, preferred_model):
        if attempt_model in tried:
            continue
        tried.append(attempt_model)
        try:
            text = _gemini_call_with_retry(api_key, attempt_model, prompt)
            break
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                print('[roi_detector] Gemini model %r not found (HTTP 404) -- '
                      'trying another.' % attempt_model)
                continue
            print('[roi_detector] Gemini call failed (HTTP %s) -- falling back to heuristic.'
                  % exc.code)
            return None
        except Exception as exc:
            print('[roi_detector] Gemini call failed (%s) -- falling back to heuristic.' % exc)
            return None
    else:
        print('[roi_detector] No working Gemini model found -- falling back to heuristic.')
        return None

    if not text:
        print('[roi_detector] Empty Gemini response -- falling back to heuristic.')
        return None

    names = parse_llm_response(text)
    if not names:
        print('[roi_detector] Could not parse Gemini response -- falling back to heuristic.')
        return None
    return names


def llm_detect(app_dir, top_n=1, model=None, provider=None):
    """
    Dispatches to the requested provider's *_detect() implementation
    (default: DEFAULT_PROVIDER, i.e. the ROI_DETECTOR_PROVIDER env var, or
    'anthropic' if that's unset). Both providers share the exact same
    return contract: a list of function names, or None meaning "fall back
    to heuristic_detect()".
    """
    provider = (provider or DEFAULT_PROVIDER).strip().lower()
    if provider == 'anthropic':
        return anthropic_detect(app_dir, top_n=top_n, model=model)
    if provider == 'gemini':
        return gemini_detect(app_dir, top_n=top_n, model=model)
    print('[roi_detector] Unknown provider %r (expected "anthropic" or "gemini") '
          '-- skipping LLM detection.' % provider)
    return None


# ─────────────────────────── result caching ──────────────────────────────────
# LLM calls aren't perfectly reproducible, and separate invocations (e.g.
# roi_detector.py to preview, then roi_extractor.py/roi_circuit_check.py to
# act) would otherwise each make their own fresh call and could disagree.
# Caching keyed on the inputs that affect the answer keeps repeated calls
# consistent and avoids redundant LLM calls during iterative development.

def _cache_path(app_dir):
    return os.path.join(app_dir, ROI_CACHE_FILENAME)


def _load_cache(app_dir):
    try:
        with open(_cache_path(app_dir)) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def _save_cache(app_dir, key, names, method):
    try:
        with open(_cache_path(app_dir), 'w') as f:
            json.dump({'key': key, 'names': names, 'method': method}, f, indent=2)
    except OSError:
        pass  # caching is a best-effort convenience, never a hard requirement


# ─────────────────────────── top-level entry point ───────────────────────────

def detect_roi(app_dir, top_n=1, model=None, force_heuristic=False, provider=None,
                force_redetect=False):
    """
    Returns (func_names, method): a validated, non-empty list of real
    function names in <app_dir>/main (or [] if detection failed), and which
    path produced it ('<provider>' or 'heuristic', or whatever was cached).

    Cached to <app_dir>/.roi_detect_cache.json, keyed on (provider, model,
    top_n, force_heuristic). A cache hit re-validates the cached names
    against the binary's current symbol table (so a stale cache from before
    a recompile is treated as a miss). force_redetect=True skips the cache
    and overwrites it with the fresh result.
    """
    resolved_provider = (provider or DEFAULT_PROVIDER).strip().lower()
    cache_key = {'provider': resolved_provider, 'model': model, 'top_n': top_n,
                 'force_heuristic': force_heuristic}

    if not force_redetect:
        cached = _load_cache(app_dir)
        if cached and cached.get('key') == cache_key:
            validated = validate_function_names(app_dir, cached.get('names') or [])
            if validated:
                print('[roi_detector] Using cached ROI selection (%s) from %s: %s -- '
                      'pass force_redetect=True / --force-redetect to override.'
                      % (cached.get('method'), _cache_path(app_dir), ','.join(validated)))
                return validated, cached.get('method')

    names, method = None, None
    binary_path = os.path.join(app_dir, 'main')

    if not force_heuristic:
        llm_names = llm_detect(app_dir, top_n=top_n, model=model, provider=provider)
        validated = validate_function_names(app_dir, llm_names) if llm_names else []
        if validated:
            names = filter_trace_visible(app_dir, binary_path, validated)
            method = resolved_provider
        elif llm_names:
            print('[roi_detector] LLM suggested %s but none resolved in the binary '
                  '-- falling back to heuristic.' % llm_names)

    if not names:
        heuristic_names = heuristic_detect(app_dir, top_n=top_n)
        validated = validate_function_names(app_dir, heuristic_names)
        if validated:
            names = filter_trace_visible(app_dir, binary_path, validated)
            method = 'heuristic'

    if names:
        _save_cache(app_dir, cache_key, names, method)

    return names or [], method


def usage():
    print('Usage: %s -a <app_dir> [--provider <name>] [--model <name>] [--top-n <num>] '
          '[--heuristic-only]' % sys.argv[0])
    print('  -a <path>          Application directory (must contain "adjlist" from')
    print('                     extractor.py and a compiled "main" binary)')
    print('  --provider <name>  LLM provider: "anthropic" or "gemini"')
    print('                     (default: %s, override via ROI_DETECTOR_PROVIDER env var)'
          % DEFAULT_PROVIDER)
    print('  --top-n <num>      Number of ROI functions to select (default: 1)')
    print('  --model <name>     Model id to use for LLM detection (meaning depends on')
    print('                     --provider):')
    print('                       anthropic default: %s (env ROI_DETECTOR_MODEL)'
          % DEFAULT_ANTHROPIC_MODEL)
    print('                       gemini default:    resolved live via ListModels')
    print('                                          (env ROI_DETECTOR_GEMINI_MODEL)')
    print('  --heuristic-only   Skip the LLM call and use the static heuristic directly')
    print('  --force-redetect   Ignore any cached ROI selection for this app_dir (see')
    print('                     %s) and query the detector fresh' % ROI_CACHE_FILENAME)
    print()
    print('API keys (env vars, never via CLI flag): ANTHROPIC_API_KEY for the anthropic')
    print('provider; GEMINI_API_KEY or GOOGLE_API_KEY for the gemini provider.')


if __name__ == '__main__':
    app_dir = None
    top_n = 3
    model = None
    provider = None
    heuristic_only = False
    force_redetect = False
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'ha:',
                                    ['top-n=', 'model=', 'provider=', 'heuristic-only',
                                     'force-redetect'])
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
        elif opt == '--force-redetect':
            force_redetect = True
    if not app_dir:
        usage(); sys.exit(2)

    names, method = detect_roi(app_dir, top_n=top_n, model=model,
                                force_heuristic=heuristic_only, provider=provider,
                                force_redetect=force_redetect)
    if names:
        print('[roi_detector] Selected ROI function(s) via %s: %s' % (method, ','.join(names)))
        print(','.join(names))
    else:
        print('[roi_detector] Failed to detect any ROI function.')
        sys.exit(1)
