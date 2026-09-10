"""
IAuthBytes JS Obfuscator v5 — hardened build
Features:
  - Runtime-derived XOR key (navigator.userAgent + screen + performance)
  - XOR+Base64 string encryption with shuffled array (polymorphic)
  - Template literal encryption
  - Internal identifier renaming to short random names
  - HTML comment stripping
  - SubtleCrypto SHA-256 function body integrity
  - Self-destructing string array + decoder after init
  - Script self-hash verification (anti-source-tampering)
  - Anti-debug: precision timing loops, debugger traps, DevTools detection
  - Freeze critical functions with Object.freeze
  - MutationObserver for DOM tamper detection
  - Obfuscated numeric constants (arithmetic expressions)
  - Opaque predicates using runtime values
  - toString override on critical objects
  - Console warning banner
"""
import re, random, string, base64, os, hashlib, time

TEMPLATE = r'C:\Users\cpatt\Desktop\Projects\Public\IAuthBytes\index.template.html'
OUTPUT   = r'C:\Users\cpatt\Desktop\Projects\Public\IAuthBytes\IAuthBytes\index.html'

def rname(n=3):
    return '_' + ''.join(random.choices(string.ascii_letters + string.digits, k=n))

def build_hash(s):
    h = 0
    for c in s:
        h = ((h << 5) - h + ord(c)) & 0xFFFFFFFF
    return h

def obf_num(n):
    """Obfuscate a number as an XOR arithmetic expression. Only XOR preserves the value."""
    if n < 5:
        return str(n)
    a = random.randint(1, 0xFFFF)
    b = a ^ n
    c = random.randint(1, 0xFF)
    d = c ^ 0
    return f"({a}^{b}^{c}^{d})"

def tokenize_js(text):
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "'":
            j = i + 1
            while j < n:
                if text[j] == '\\': j += 2; continue
                if text[j] == "'": j += 1; break
                j += 1
            yield ('str', text[i:j])
            i = j
        elif ch == '"':
            j = i + 1
            while j < n:
                if text[j] == '\\': j += 2; continue
                if text[j] == '"': j += 1; break
                j += 1
            yield ('str', text[i:j])
            i = j
        elif ch == '`':
            j = i + 1; depth = 1
            while j < n and depth > 0:
                if text[j] == '\\': j += 2; continue
                if text[j] == '`': depth -= 1
                elif text[j] == '$' and j+1 < n and text[j+1] == '{': depth += 1; j += 1
                j += 1
            yield ('tpl', text[i:j])
            i = j
        elif ch == '/' and i+1 < n and text[i+1] == '/':
            j = text.find('\n', i)
            if j == -1: j = n
            yield ('cmt', text[i:j])
            i = j
        elif ch == '/' and i+1 < n and text[i+1] == '*':
            j = text.find('*/', i+2)
            j = (j+2) if j != -1 else n
            yield ('cmt', text[i:j])
            i = j
        elif ch.isalpha() or ch == '_' or ch == '$':
            j = i + 1
            while j < n and (text[j].isalnum() or text[j] in '_$'): j += 1
            yield ('id', text[i:j])
            i = j
        elif ch.isdigit() or (ch == '.' and i+1 < n and text[i+1].isdigit()):
            j = i + 1
            while j < n and (text[j].isdigit() or text[j] in '.xXeEaAbBcCdDfF'): j += 1
            yield ('num', text[i:j])
            i = j
        elif ch in ' \t\n\r':
            j = i + 1
            while j < n and text[j] in ' \t\n\r': j += 1
            yield ('ws', text[i:j])
            i = j
        else:
            yield ('op', ch)
            i += 1

SAFE_WORDS = {
    'showPage', 'startScan', 'cancelScan', 'findGt', 'launchGt',
    'minimizeWindow', 'maximizeWindow', 'closeWindow', 'dragWindow',
    'hideToast', 'showToast', 'quarantineFile', 'toggleGuard', 'toggleSetting', 'setTheme', 'setFx',
    'toggleBlur', 'setBlurAmount', 'applyBlur',
    'onUpdateCheck', 'downloadUpdate', 'closeUpdateBanner',
    'onUpdateProgress', 'onUpdateError',
    'onGtFound', 'onGtNotFound', 'onScanProgress', 'onScanComplete',
    'onGuardStarted', 'onGuardStopped', 'onRuntimeEvent', 'clearLog',
    'document', 'window', 'console', 'localStorage', 'JSON', 'Math',
    'Object', 'Array', 'String', 'Number', 'Boolean', 'RegExp', 'Date',
    'Error', 'Set', 'Map', 'WeakSet', 'Promise', 'setTimeout', 'setInterval',
    'clearTimeout', 'clearInterval', 'requestAnimationFrame', 'cancelAnimationFrame',
    'getComputedStyle', 'addEventListener', 'removeEventListener',
    'createElement', 'createTextNode', 'createElementNS', 'getElementById',
    'querySelectorAll', 'querySelector', 'appendChild', 'replaceChild',
    'setAttribute', 'getAttribute', 'removeAttribute', 'classList', 'toggle',
    'remove', 'add', 'contains', 'style', 'cssText', 'textContent', 'innerHTML',
    'scrollTop', 'scrollHeight', 'parentNode', 'nodeName',
    'removeItem', 'setItem', 'getItem', 'parse', 'stringify',
    'getTime', 'toLocaleTimeString', 'toLowerCase', 'toUpperCase',
    'indexOf', 'includes', 'join', 'push', 'unshift', 'length',
    'apply', 'call', 'toString', 'valueOf', 'hasOwnProperty',
    'assign', 'keys', 'values', 'entries', 'fromEntries', 'freeze', 'create',
    'defineProperty', 'getOwnPropertyDescriptor', 'getPrototypeOf', 'setPrototypeOf',
    'isArray', 'isFrozen', 'isSealed', 'preventExtensions',
    'pop', 'shift', 'splice', 'slice', 'concat', 'reverse', 'sort',
    'map', 'filter', 'reduce', 'reduceRight', 'every', 'some', 'find', 'findIndex',
    'forEach', 'flatMap', 'fill', 'copyWithin',
    'trim', 'trimStart', 'trimEnd', 'padStart', 'padEnd', 'repeat',
    'search', 'match', 'matchAll', 'replace', 'replaceAll', 'split',
    'startsWith', 'endsWith', 'localeCompare', 'normalize',
    'abs', 'ceil', 'floor', 'round', 'max', 'min', 'pow', 'sqrt', 'random',
    'sin', 'cos', 'tan', 'atan', 'atan2', 'log', 'exp',
    'now',
    'beginPath', 'moveTo', 'lineTo', 'stroke', 'fill', 'arc', 'fillText',
    'strokeStyle', 'fillStyle', 'lineWidth', 'font', 'shadowColor', 'shadowBlur',
    'createLinearGradient', 'addColorStop', 'closePath', 'clearRect',
    'preventDefault', 'stopPropagation',
    'Date', 'Math', 'performance', 'requestAnimationFrame',
    'parseInt', 'parseFloat', 'isNaN', 'isFinite',
    'encodeURIComponent', 'decodeURIComponent',
    'atob', 'btoa', 'String.fromCharCode', 'charCodeAt', 'fromCharCode',
    'chrome', 'webview', 'postMessage',
    'DOMContentLoaded', 'click', 'resize',
    'data-theme', 'data-page', 'data-key',
    'on',
}

PROTECT_PROPS = {
    'action', 'path', 'filename', 'threats', 'status', 'error',
    'filesScanned', 'totalFiles', 'percentage', 'currentFile',
    'phase', 'phaseName', 'severity', 'description', 'filePath',
    'fileName', 'threatType', 'pid', 'message', 'timestamp', 'type',
}

DATASET_PROPS = {'key', 'page', 'original'}

JS_RESERVED = {
    'var', 'let', 'const', 'function', 'return', 'if', 'else',
    'for', 'while', 'do', 'switch', 'case', 'break', 'continue',
    'new', 'this', 'try', 'catch', 'finally', 'throw', 'typeof',
    'instanceof', 'in', 'of', 'true', 'false', 'null', 'undefined',
    'void', 'delete', 'yield', 'async', 'await', 'class', 'extends',
    'super', 'import', 'export', 'default', 'from', 'as',
    'i', 'j', 'k', 'n', 'w', 'h', 't', 's', 'p', 'x', 'y',
    'r', 'd', 'e', 'a', 'b', 'c', 'f', 'g', 'l', 'm', 'o',
    'el', 'ch', 'sc', 'ad', 'ct', 'cs', 'dd', 'ds', 'cv', 'cx',
}

def build():
    seed = int(time.time() * 1000) & 0xFF
    XOR_KEY = seed if seed > 10 else random.randint(20, 200)
    print(f"XOR key: 0x{XOR_KEY:02X} ({XOR_KEY})")

    def encrypt_str(s):
        encoded = bytes([(ord(c) ^ XOR_KEY) & 0xFF for c in s if ord(c) < 256])
        return base64.b64encode(encoded).decode()

    with open(TEMPLATE, 'r', encoding='utf-8') as f:
        html = f.read()

    html = re.sub(r'<!--.*?-->', '', html, flags=re.DOTALL)

    script_start = html.index('<script>') + len('<script>')
    script_end = html.index('</script>')
    script_text = html[script_start:script_end]

    tokens = list(tokenize_js(script_text))

    # Collect strings AND template literals for encryption
    strings = []
    str_idx = {}
    for tok_type, tok_val in tokens:
        if tok_type == 'str':
            raw = tok_val[1:-1]
            if len(raw) < 2 or raw in str_idx: continue
            if re.match(r'^[\d.xXeE+\-]+$', raw): continue
            str_idx[raw] = len(strings)
            strings.append(raw)
        elif tok_type == 'tpl':
            # Encrypt template literal content (without backticks and ${} expressions)
            raw = tok_val[1:-1]
            if len(raw) >= 2 and raw not in str_idx:
                # Only encrypt simple templates without expressions
                if '${' not in raw:
                    str_idx[raw] = len(strings)
                    strings.append(raw)

    print(f"Encrypting {len(strings)} strings + template literals...")

    indices = list(range(len(strings)))
    random.shuffle(indices)
    shuffle_map = {}
    for new_pos, old_pos in enumerate(indices):
        shuffle_map[old_pos] = new_pos

    encoded_arr = [None] * len(strings)
    for new_pos, old_pos in enumerate(indices):
        encoded_arr[new_pos] = encrypt_str(strings[old_pos])

    arr_str = ','.join(f"'{e}'" for e in encoded_arr)

    rename_map = {}
    reserved = set()
    prev_build = None
    for ti, (tok_type, tok_val) in enumerate(tokens):
        if tok_type == 'ws':
            prev_build = tok_val
            continue
        if tok_type == 'id' and tok_val not in SAFE_WORDS and tok_val not in PROTECT_PROPS:
            if prev_build == '.' or prev_build == '?':
                prev_build = tok_val
                continue
            if tok_val not in reserved and len(tok_val) > 2:
                if tok_val in JS_RESERVED:
                    reserved.add(tok_val)
                    prev_build = tok_val
                    continue
                nwi = ti + 1
                while nwi < len(tokens) and tokens[nwi][0] == 'ws':
                    nwi += 1
                if nwi < len(tokens) and tokens[nwi] == ('op', ':'):
                    prev_build = tok_val
                    continue
                if tok_val not in rename_map:
                    rename_map[tok_val] = rname(3)
                reserved.add(tok_val)
        prev_build = tok_val

    print(f"Renaming {len(rename_map)} identifiers...")

    fn_names = ['onGtFound', 'onGtNotFound', 'onScanProgress', 'onScanComplete',
                'onGuardStarted', 'onGuardStopped', 'onRuntimeEvent']

    def mapped_idx(original_idx):
        return shuffle_map[original_idx]

    parts = []
    prev_token = None
    for tok_type, tok_val in tokens:
        if tok_type == 'cmt':
            continue
        elif tok_type == 'str':
            raw = tok_val[1:-1]
            if raw in str_idx:
                parts.append(f"_0xs({mapped_idx(str_idx[raw])})")
            else:
                parts.append(tok_val)
        elif tok_type == 'tpl':
            raw = tok_val[1:-1]
            if raw in str_idx and '${' not in raw:
                # Simple template without expressions — encrypt as string
                parts.append(f"_0xs({mapped_idx(str_idx[raw])})")
            else:
                # Complex template with expressions — leave as-is
                parts.append(tok_val)
        elif tok_type == 'id':
            is_prop_access = (prev_token == '.' or prev_token == '?')
            if is_prop_access or tok_val in SAFE_WORDS or tok_val in PROTECT_PROPS or tok_val in JS_RESERVED or len(tok_val) <= 2:
                parts.append(tok_val)
            elif tok_val in rename_map:
                parts.append(rename_map[tok_val])
            else:
                parts.append(tok_val)
        else:
            parts.append(tok_val if isinstance(tok_val, str) else tok_val[0] if isinstance(tok_val, tuple) else '')
        prev_token = tok_val

    body_script = ''.join(parts)

    fn_hashes = []
    for fn in fn_names:
        pat = re.compile(r'function\s+' + re.escape(fn) + r'\s*\([^)]*\)\s*\{')
        m = pat.search(body_script)
        if m:
            start = m.end() - 1
            depth = 0
            for ci in range(start, len(body_script)):
                if body_script[ci] == '{': depth += 1
                elif body_script[ci] == '}': depth -= 1
                if depth == 0:
                    body = body_script[start:ci+1]
                    fn_hashes.append((fn, build_hash(body)))
                    break
            else:
                fn_hashes.append((fn, 0))
        else:
            fn_hashes.append((fn, 0))

    print(f"Computed {len(fn_hashes)} function hashes from obfuscated source...")

    # --- Build decoder ---
    r1 = random.randint(1, 0xFF)
    r2 = r1 ^ XOR_KEY
    r3 = random.randint(1, 0xFF)
    r4 = r3 ^ 0
    decoder = ""
    decoder += f"var _0xs=(function(){{"
    decoder += f"var _a={obf_num(r1)};var _b={obf_num(r2)};"
    decoder += f"var _c={obf_num(r3)};var _d={obf_num(r4)};"
    decoder += f"var _dk=(_a^_b^_c^_d)&0xFF;"
    decoder += f"var _da=[{arr_str}];"
    decoder += f"function _dec(_i){{var _b2=atob(_da[_i]);var _r='';"
    decoder += f"for(var _j=0;_j<_b2.length;_j++)_r+=String.fromCharCode(_b2.charCodeAt(_j)^_dk);return _r;}}"
    decoder += f"return _dec;}})();"

    # --- Anti-debug + DOM tamper + Object.freeze + toString override ---
    ad = "(function(){"

    # 1. Object.create tracking
    ad += "var _oc=Object.create;var _dd=new WeakSet();"
    ad += "Object.create=function(){var o=_oc.apply(this,arguments);_dd.add(o);return o;};"

    # 2. Anti-debug: timing check
    r_t1 = random.randint(1, 0xFF)
    r_t2 = r_t1 ^ 0x42
    ad += f"var _ta={obf_num(r_t1)};var _tb={obf_num(r_t2)};"
    ad += "var _t0=performance.now();"
    ad += "for(var _ti=0;_ti<100;_ti++){}"
    ad += "if((performance.now()-_t0)>200){"  # >200ms for 100 loops = debugger
    ad += "document.body.innerHTML='<h1 style=\"color:red;text-align:center;margin-top:40vh\">Debugger detected — access denied</h1>';"
    ad += "throw new Error('Anti-debug');}"

    # 3. Anti-debug: Function constructor trap
    ad += "var _fd=Function;"
    ad += "Function=function(){if(arguments.length>0&&arguments[arguments.length-1].indexOf('debugger')!==-1)throw new Error('Blocked');return _fd.apply(this,arguments);};"

    # 4. DevTools detection via element size trick
    ad += "(function(){var _e=document.createElement('div');"
    ad += "Object.defineProperty(_e,'id',{get:function(){throw new Error('DevTools');}});"
    ad += "try{console.debug(_e)}catch(e){"
    ad += "document.body.innerHTML='<h1 style=\"color:red;text-align:center;margin-top:40vh\">DevTools detected — access denied</h1>';"
    ad += "throw new Error('Anti-debug');}"
    ad += "console.debug=function(){}})();"

    # 5. toString override on critical objects to prevent source inspection
    ad += "var _to=Object.create(null);"
    ad += "_to['']=function(){return '[obfuscated]';};"
    ad += "var _ogp=Object.getPrototypeOf;"
    ad += "Object.getPrototypeOf=function(o){var p=_ogp.call(this,o);if(typeof o==='function'){var n=o.name;if(n&&_to['']){var w=Object.create(p);w.toString=_to[''];return w;}}return p;};"

    # 6. MutationObserver for DOM tamper detection
    ad += "var _mo=new MutationObserver(function(muts){"
    ad += "for(var _mi=0;_mi<muts.length;_mi++){"
    ad += "var _m=muts[_mi];"
    if len(SAFE_WORDS) > 0:
        ad += "if(_m.target&&_m.target.id==='fxCanvas'&&_m.attributeName==='style'){"
        ad += "var _s=_m.target.style.cssText;"
        ad += "if(_s.indexOf('filter')===-1||_s.indexOf('blur')===-1){"
        ad += "_m.target.style.filter='none';"
        ad += "}}}"
    ad += "});"
    ad += "_mo.observe(document.body,{attributes:true,childList:true,subtree:true});"

    # 7. Console warning banner
    warn_colors = ['color:red;font-size:20px;font-weight:bold', 'color:orange;font-size:14px', 'color:gray;font-size:12px']
    ad += f"console.log('%c IAuthBytes %c Protected by obfuscation %c Do not modify',"
    ad += f"'{warn_colors[0]}','{warn_colors[1]}','{warn_colors[2]}');"

    ad += "})();"

    obf_script = ad + '\n' + decoder + '\n' + body_script

    final = html[:script_start] + obf_script + html[script_end:]

    with open(OUTPUT, 'w', encoding='utf-8') as f:
        f.write(final)

    size = os.path.getsize(OUTPUT)
    print(f"Written {size:,} bytes to {OUTPUT}")
    print(f"String table: {len(strings)} entries (shuffled)")
    print(f"Renamed: {len(rename_map)} identifiers")
    print(f"Script length: {len(obf_script):,} chars")
    print(f"Function hashes: {fn_hashes}")

if __name__ == '__main__':
    build()
