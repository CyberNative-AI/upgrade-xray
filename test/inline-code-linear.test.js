// Inline code in shell commands and owner e-mail addresses are found in one pass over each
// string, and give exactly what the previous regexes gave on ordinary text.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanJs, inlineCode } from '../src/js-scan.js';
import { emailsIn, pypiOwners } from '../src/registry.js';

const SRC = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'src');

// Every string of up to n tokens.
function* joins(tokens, n) {
    yield '';
    let level = [''];
    for (let i = 0; i < n; i++) {
        const next = [];
        for (const p of level) for (const t of tokens) { next.push(p + t); yield p + t; }
        level = next;
    }
}

const OLD_JS = /\beval\(|base64\s+-d|(curl|wget)\b[^|]{0,200}\|\s*(ba)?sh\b|powershell[^\n]*\s-e(nc|ncodedcommand)?\b|\bnode\s+-e\s|python[0-9.]*\s+-c\s/i;

test('inlineCode gives what the previous pattern matched', () => {
    const tokens = ['powershell', 'PowerShell.exe', ' -e', ' -enc', ' -EncodedCommand', ' -ex', '\n', '\n-e', ' ', 'x',
        'curl u', ' | sh', '|bash', 'eval(', 'node -e ', 'python3 -c ', 'base64 -d', 'wget'];
    let n = 0; let hits = 0;
    for (const s of joins(tokens, 4)) {
        const want = s.match(OLD_JS)?.[0] ?? null;
        assert.equal(inlineCode(s), want, JSON.stringify(s));
        n++; if (want) hits++;
    }
    assert.ok(n > 100000 && hits > n / 4, `${n} strings, ${hits} with inline code`);
});

test('a shell call reports inline code from its arguments, nested shell calls included', () => {
    const src = [
        'const cp = require("child_process");',
        'cp.exec(cp.spawn("node -e 1"));',
        'cp.exec(cp["curl u | sh"].exec("python3 -c 1"));',
        'cp.execSync(`powershell -NoProfile -EncodedCommand ${x} -enc A\npowershell -e B`);',
        'cp.exec("ls", { cwd: "eval(" });',
        'cp.exec(f("plain"), "no code");',
        'new cp.exec(spawn(exec(`a${spawn("curl x |sh")}b`, "eval(")), "node -e x");',
    ].join('\n');
    const got = scanJs(src).signals.filter((s) => s.kind === 'encoded-exec').map((s) => `${s.line} ${s.detail}`);
    assert.deepEqual(got, [
        '2 spawn() launched with inline code: node -e ',
        '2 exec() launched with inline code: node -e ',
        '3 exec() launched with inline code: python3 -c ',
        '3 exec() launched with inline code: curl u | sh',
        '4 execSync() launched with inline code: powershell -NoProfile -EncodedCommand',
        '6 exec() launched with inline code: eval(',
        '8 spawn() launched with inline code: curl x |sh',
        '8 exec() launched with inline code: curl x |sh',
        '8 spawn() launched with inline code: curl x |sh',
        '8 exec() launched with inline code: curl x |sh',
    ]);
});

test('emailsIn gives what the previous regex found', () => {
    const old = (s) => s.match(/[\w.+-]+@[\w.-]+/g) || [];
    const tokens = ['a', 'B.c', '+', '-', '@', 'x.org', ' ', '<', '>', ',', '_', 'é'];
    let n = 0;
    for (const s of joins(tokens, 5)) { assert.deepEqual(emailsIn(s), old(s), JSON.stringify(s)); n++; }
    assert.ok(n > 200000);
    assert.deepEqual(pypiOwners({ author_email: 'Jane Doe <Jane@Example.org>, bob+ci@y.co', maintainer_email: 'a@b+c@d', project_urls: { Source: 'https://github.com/Org/x/' } }),
        ['e:jane@example.org', 'e:bob+ci@y.co', 'e:a@b', 'e:+c@d', 'gh:org']);
});

test('Python inline_code gives what the previous pattern matched', () => {
    const script = String.raw`
import itertools, re, sys
sys.path.insert(0, sys.argv[1])
import py_scan
old = re.compile(r"exec\(|eval\(|b64decode|base64\s+-d|\|\s*(ba)?sh\b|powershell[^\n]*-e(nc|ncodedcommand)?\b|python[0-9.]*\s+-c\b|marshal\.loads|zlib\.decompress", re.I)
tokens = ["powershell", "POWERſHELL", "-e", "-enc", "-EncodedCommand", "-ex", "\n", " ", "x", "| sh", "exec(", "python3 -c", "b64decode", "base64 -d"]
n = hits = 0
for k in range(5):
    for t in itertools.product(tokens, repeat=k):
        s = "".join(t)
        m = old.search(s)
        want = m.group(0) if m else None
        if py_scan.inline_code(s) != want:
            print("DIFF", repr(s), repr(py_scan.inline_code(s)), repr(want))
            sys.exit(1)
        n += 1
        hits += want is not None
print(n, hits)
`;
    const r = spawnSync(process.env.PYTHON || 'python3', ['-I', '-B', '-c', script, SRC], { encoding: 'utf8' });
    assert.equal(r.status, 0, r.stdout + r.stderr);
    const [n, hits] = r.stdout.trim().split(' ').map(Number);
    assert.ok(n > 40000 && hits > n / 4, r.stdout);
});
