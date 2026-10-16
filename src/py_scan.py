"""Static scan of Python sources: capabilities, string literals and public names.

Reads {"files": [{"path", "source"}], "exports": [paths]} as JSON on stdin and writes
JSON results to stdout. Sources are parsed with the ast module; nothing is imported
or executed.
"""
import ast
import json
import re
import sys

NETWORK = {
    "socket", "urllib", "urllib.request", "urllib2", "urllib3", "requests", "http.client", "httplib",
    "httpx", "aiohttp", "ftplib", "smtplib", "telnetlib", "paramiko", "websocket", "websockets",
    "pycurl", "dns", "dns.resolver", "tornado.httpclient", "grequests", "ssl",
}
SHELL = {"subprocess", "pty", "commands", "pexpect", "sh", "plumbum"}
NATIVE = {"ctypes", "cffi", "_ctypes"}
SHELL_CALLS = re.compile(r"^(os\.(system|popen|popen[234]|exec\w+|spawn\w+|startfile|posix_spawn\w*)|subprocess\.\w+|pty\.spawn|commands\.\w+)$")
NET_CALLS = re.compile(r"^(urllib\.request\.urlopen|urlopen|urllib\.urlopen|urllib2\.urlopen|requests\.(get|post|put|patch|delete|request|head|Session)|httpx\.\w+|socket\.(socket|create_connection)|http\.client\.\w+Connection)$")
DECODERS = re.compile(r"(^|\.)(b64decode|b32decode|b16decode|b85decode|a85decode|decodebytes|decodestring|unhexlify|fromhex|decompress|loads|rot13|decode)$")
FETCHERS = re.compile(r"(urlopen|requests\.get|\.get|\.read|\.text|\.content)$")
OBF_NAME = re.compile(r"^[OoIl0_]{8,}$|^_{2,}[0-9a-f]{6,}$")
PY_INTERP = re.compile(r"^(python[0-9.]*|pythonw|py)(\.exe)?$", re.I)
PY_COMMAND = re.compile(r"(^|[\s/\\])python[0-9.]*w?(\.exe)?\s+(?!-)\S", re.I)


def dotted(node):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    elif isinstance(node, ast.Call):
        parts.append(dotted(node.func) + "()")
    else:
        parts.append("?")
    return ".".join(reversed(parts))


def contains_call(node, pattern):
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call) and pattern.search(dotted(sub.func)):
            return dotted(sub.func)
        if isinstance(sub, ast.Attribute) and pattern.search(dotted(sub)):
            return dotted(sub)
    return None


INLINE_CODE = re.compile(r"exec\(|eval\(|b64decode|base64\s+-d|\|\s*(ba)?sh\b|powershell[^\n]*-e(nc|ncodedcommand)?\b|python[0-9.]*\s+-c\b|marshal\.loads|zlib\.decompress", re.I)


def strings_in(node):
    for sub in ast.walk(node):
        if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
            yield sub.value


class Scanner(ast.NodeVisitor):
    def __init__(self):
        self.depth = 0
        self.signals = []
        self.strings = set()
        self.aliases = {}
        self.env_bulk = False
        self.network = False
        self.eval_like = False
        self.long_encoded = 0
        self.inline_exec = False
        self.obf_names = 0
        self.spawn_py = False
        self.net_call = False

    def push(self, kind, detail, node=None):
        self.signals.append({"kind": kind, "detail": str(detail)[:120], "line": getattr(node, "lineno", 0)})

    def on_module(self, name, node):
        base = name.split(".")[0]
        for cand in (name, base):
            if cand in NETWORK:
                self.push("network", "module " + cand, node)
                self.network = True
                break
        if base in SHELL:
            self.push("shell", "module " + base, node)
        if base in NATIVE:
            self.push("native-code", "module " + base, node)

    def _nested(self, node):
        self.depth += 1
        self.generic_visit(node)
        self.depth -= 1

    visit_FunctionDef = _nested
    visit_AsyncFunctionDef = _nested
    visit_Lambda = _nested
    visit_ClassDef = _nested

    def visit_Import(self, node):
        for a in node.names:
            self.on_module(a.name, node)
            if a.asname:
                self.aliases[a.asname] = a.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module and node.level == 0:
            self.on_module(node.module, node)
            for a in node.names:
                full = node.module + "." + a.name
                self.aliases[a.asname or a.name] = full
                if full in NETWORK or node.module + "." + a.name in ("os.system", "os.popen"):
                    pass
        self.generic_visit(node)

    def resolve(self, name):
        head, _, rest = name.partition(".")
        if head in self.aliases:
            return self.aliases[head] + ("." + rest if rest else "")
        return name

    def visit_Call(self, node):
        name = self.resolve(dotted(node.func))
        if name in ("eval", "exec", "builtins.eval", "builtins.exec", "compile", "execfile"):
            arg = node.args[0] if node.args else None
            if not (isinstance(arg, ast.Constant) and isinstance(arg.value, str) and len(arg.value) < 40):
                self.push("eval", name + "()", node)
                self.eval_like = True
                if arg is not None:
                    dec = contains_call(arg, DECODERS)
                    fetch = contains_call(arg, re.compile(r"urlopen|requests\.(get|post|request)|httpx\.(get|post|request)|urllib\.request|\.urlretrieve"))
                    if dec:
                        self.push("encoded-exec", "%s(%s(...))" % (name, dec), node)
                    elif fetch:
                        self.push("encoded-exec", "%s(<downloaded: %s>)" % (name, fetch), node)
        elif name in ("__import__", "importlib.import_module"):
            arg = node.args[0] if node.args else None
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                self.on_module(arg.value, node)
            else:
                self.push("dynamic-require", name + "(<computed>)", node)
        elif SHELL_CALLS.match(name):
            self.push("shell", name + "()", node)
            if self.depth == 0:
                self.push("shell", name + "() at import time", node)
            inline = next((x for x in strings_in(node) if INLINE_CODE.search(x)), None)
            spawns_python = any(dotted(a) == "sys.executable" for a in ast.walk(node) if isinstance(a, ast.Attribute))
            if inline is not None:
                self.push("encoded-exec", "%s() launched with inline code: %s" % (name, INLINE_CODE.search(inline).group(0)), node)
            elif spawns_python and any(x == "-c" for x in strings_in(node)):
                self.push("eval", name + "(sys.executable, '-c', ...)", node)
            elif spawns_python or any(PY_INTERP.match(x.replace("\\", "/").rsplit("/", 1)[-1]) or PY_COMMAND.search(x) for x in strings_in(node)):
                # A second interpreter on a file: the usual way to start a downloaded,
                # decoded or bundled payload detached from the importing process.
                self.spawn_py = True
                self.push("python-spawn", name + "() starts a Python process", node)
                if self.depth == 0:
                    self.push("python-spawn", name + "() starts a Python process at import time", node)
        elif NET_CALLS.match(name):
            self.push("network", name + "()", node)
            self.network = True
            self.net_call = True
            if self.depth == 0:
                self.push("network", name + "() at import time", node)
        elif name in ("marshal.loads", "pickle.loads", "dill.loads") and self.eval_like:
            self.push("eval", name + "()", node)
        if name in ("json.dumps", "str", "repr", "base64.b64encode") or name.endswith((".post", ".send", ".sendall", ".write")):
            for a in node.args:
                if dotted(a) in ("os.environ", "os.environ.items()", "os.environ.copy()"):
                    self.push("env-bulk", name + "(os.environ)", node)
                    self.env_bulk = True
        self.generic_visit(node)

    def visit_For(self, node):
        it = dotted(node.iter.func) if isinstance(node.iter, ast.Call) else dotted(node.iter)
        if it in ("os.environ.items", "os.environ", "os.environ.keys", "os.environ.values"):
            self.push("env-bulk", "for ... in " + it, node)
            self.env_bulk = True
        self.generic_visit(node)

    def visit_comprehension(self, node):
        it = dotted(node.iter.func) if isinstance(node.iter, ast.Call) else dotted(node.iter)
        if it in ("os.environ.items", "os.environ", "os.environ.keys"):
            self.push("env-bulk", "comprehension over " + it, node)
            self.env_bulk = True
        self.generic_visit(node)

    def visit_Name(self, node):
        if OBF_NAME.match(node.id):
            self.obf_names += 1
        self.generic_visit(node)

    def visit_Constant(self, node):
        v = node.value
        if isinstance(v, bytes):
            try:
                v = v.decode("latin1")
            except Exception:
                v = None
        if isinstance(v, str) and len(v) >= 4:
            if len(v) > 1500 and re.fullmatch(r"[A-Za-z0-9+/=\s]+", v[:4000]):
                self.long_encoded += 1
            elif INLINE_CODE.search(v[:2000]) and re.search(r"exec\(|eval\(", v[:2000]):
                self.inline_exec = True
            self.strings.add(v[:20000])
        self.generic_visit(node)


def public_names(tree):
    names = set()
    all_list = None
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for t in targets:
                if isinstance(t, ast.Name):
                    if t.id == "__all__" and isinstance(node.value, (ast.List, ast.Tuple)):
                        all_list = [e.value for e in node.value.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)]
                    if t.id.isupper():
                        names.add(t.id)
        elif isinstance(node, ast.ImportFrom) and node.level >= 1:
            for a in node.names:
                if a.name != "*":
                    names.add(a.asname or a.name)
    if all_list is not None:
        return sorted(set(all_list)), True
    return sorted(n for n in names if not n.startswith("_")), False


def regex_fallback(src, sc):
    for m in re.finditer(r"^\s*(?:import|from)\s+([\w.]+)", src, re.M):
        sc.on_module(m.group(1), None)
    if re.search(r"\b(exec|eval)\s*\(", src):
        sc.push("eval", "exec/eval()")
        sc.eval_like = True
    if re.search(r"\bos\.(system|popen)\s*\(", src):
        sc.push("shell", "os.system/popen()")
    for m in re.finditer(r"(['\"])((?:(?!\1)[^\\\n]|\\.){4,2000})\1", src):
        sc.strings.add(m.group(2))


def scan(path, src, want_exports):
    sc = Scanner()
    parsed = True
    tree = None
    try:
        tree = ast.parse(src, filename=path)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        parsed = False
    if tree is not None:
        try:
            sc.visit(tree)
        except RecursionError:
            parsed = False
    else:
        regex_fallback(src, sc)
    if re.search(r"__pyarmor__|pyarmor_runtime|PyArmor", src[:200000]):
        sc.push("obfuscation", "PyArmor-protected code")
    if sc.obf_names >= 30:
        sc.push("obfuscation", "%d obfuscated identifier uses" % sc.obf_names)
    if sc.long_encoded and (sc.eval_like or sc.inline_exec):
        sc.push("encoded-exec", "%d long encoded string(s) plus exec/eval" % sc.long_encoded)
    if sc.long_encoded and sc.spawn_py:
        sc.push("encoded-exec", "%d long encoded string(s) plus a new Python process" % sc.long_encoded)
    if sc.net_call and sc.spawn_py:
        sc.push("encoded-exec", "downloads and starts a Python process in the same file")
    if sc.env_bulk and sc.network:
        sc.push("secret-harvest", "whole environment + network in one file")
    out = {"signals": sc.signals, "strings": sorted(sc.strings)[:5000], "parsed": parsed}
    if want_exports and tree is not None:
        out["exports"], out["hasAll"] = public_names(tree)
    return out


def main():
    sys.setrecursionlimit(5000)
    req = json.load(sys.stdin)
    want = set(req.get("exports", []))
    res = {}
    for f in req["files"]:
        try:
            res[f["path"]] = scan(f["path"], f["source"], f["path"] in want)
        except Exception as e:  # never let one file kill the batch
            res[f["path"]] = {"signals": [], "strings": [], "parsed": False, "error": type(e).__name__}
    json.dump({"results": res}, sys.stdout)


if __name__ == "__main__":
    main()
