// Run Upgrade X-Ray over labelled compromised versions from the Datadog malicious
// packages dataset. "Before" is the closest earlier clean version from the registry;
// "after" is the compromised sample, read in memory.
//
//   node fixtures/run-malicious.js DATASET_DIR OUT.jsonl [--only dev|holdout] [--limit N]
import fs from 'node:fs';
import path from 'node:path';
import semver from 'semver';
import { loadSample } from './sample-reader.js';
import { splitOf } from './split.js';
import { npmSnapshot, pypiSnapshot } from '../src/snapshot.js';
import { diffSnapshots } from '../src/diff.js';
import { snapshotFromArchive, enrichNewDeps, packageOwners } from '../src/analyze.js';
import { npmPackument, npmTarball, pypiProject, pypiPickArtifacts, pypiFile } from '../src/registry.js';
import { rescore } from '../src/analyze.js';

const [dataset, outPath, ...rest] = process.argv.slice(2);
const only = rest.includes('--only') ? rest[rest.indexOf('--only') + 1] : null;
const limit = rest.includes('--limit') ? Number(rest[rest.indexOf('--limit') + 1]) : Infinity;
const CONC = 6;


function pyCmp(a, b) {
    const pa = a.split(/[.+-]|(?<=\d)(?=[a-z])|(?<=[a-z])(?=\d)/i).map((x) => (/^\d+$/.test(x) ? Number(x) : x));
    const pb = b.split(/[.+-]|(?<=\d)(?=[a-z])|(?<=[a-z])(?=\d)/i).map((x) => (/^\d+$/.test(x) ? Number(x) : x));
    for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
        const x = pa[i] ?? 0; const y = pb[i] ?? 0;
        if (x === y) continue;
        if (typeof x === 'number' && typeof y === 'number') return x - y;
        if (typeof x === 'number') return 1; // 1.0 > 1.0rc1
        if (typeof y === 'number') return -1;
        return x < y ? -1 : 1;
    }
    return 0;
}

function listSamples() {
    const out = [];
    for (const eco of ['npm', 'pypi']) {
        const base = path.join(dataset, 'samples', eco, 'compromised_lib');
        const manifest = JSON.parse(fs.readFileSync(path.join(dataset, 'samples', eco, 'manifest.json'), 'utf8'));
        for (const dir of fs.readdirSync(base).sort()) {
            const name = eco === 'npm' && dir.startsWith('@') ? dir.replace(/^@([^@]+)@/, '@$1/') : dir;
            for (const ver of fs.readdirSync(path.join(base, dir))) {
                const zips = fs.readdirSync(path.join(base, dir, ver)).filter((f) => f.endsWith('.zip'));
                if (!zips.length) continue;
                const date = (zips[0].match(/^(\d{4}-\d{2}-\d{2})/) || [])[1] || null;
                const bad = manifest[name] ?? manifest[dir] ?? null;
                out.push({ ecosystem: eco, name, version: ver, date, zip: path.join(base, dir, ver, zips[0]), malicious: Array.isArray(bad) ? bad : [ver] });
            }
        }
    }
    return out;
}

const CODE = /\.((c|m)?jsx?|(c|m)?tsx?|py|pyw|pth|sh|bat|ps1|node|so|pyd|dll|exe)$/i;

/** Is the sample a published artifact that differs from the clean version in code? */
export function comparability(oldSnap, newSnap, files) {
    const keys = [...files.keys()];
    if (keys.some((k) => k.startsWith('.git/') || k.includes('/.git/'))) return 'not-an-artifact (git checkout)';
    const code = [...newSnap.files].filter(([p]) => CODE.test(p));
    if (!code.length) return 'no code in sample';
    const same = code.every(([p, f]) => oldSnap.files.get(p)?.hash === f.hash);
    const sameScripts = JSON.stringify(oldSnap.installScripts) === JSON.stringify(newSnap.installScripts);
    const sameDeps = JSON.stringify(Object.keys(oldSnap.deps).sort()) === JSON.stringify(Object.keys(newSnap.deps).sort());
    if (same && sameScripts && sameDeps) return 'code identical to clean version';
    return 'yes';
}

async function runOne(s) {
    const t0 = Date.now();
    const rec = { ecosystem: s.ecosystem, name: s.name, version: s.version, date: s.date, split: splitOf(s.name) };
    try {
        const sample = loadSample(fs.readFileSync(s.zip), s.ecosystem);
        rec.sampleKind = sample.kind;
        rec.sampleFiles = sample.files.size;
        let before;
        let oldSnap = null;
        if (s.ecosystem === 'npm') {
            const doc = await npmPackument(s.name);
            const vers = Object.keys(doc.versions || {}).filter((v) => semver.valid(v) && semver.lt(v, s.version) && !s.malicious.includes(v) && !semver.prerelease(v));
            before = semver.rsort(vers)[0] || null;
            if (before) {
                const t = await npmTarball(s.name, before, doc.versions[before]);
                oldSnap = await snapshotFromArchive('npm', t.buf, t.filename);
            }
        } else {
            const doc = await pypiProject(s.name);
            const vers = Object.entries(doc.releases || {}).filter(([v, files]) => files.length && pyCmp(v, s.version) < 0 && !s.malicious.includes(v) && !/(a|b|rc|dev)\d*$/i.test(v));
            vers.sort((a, b) => pyCmp(b[0], a[0]));
            const pick = vers.find(([, files]) => pypiPickArtifacts(files, files).some((p) => p.kind === sample.kind));
            before = pick ? pick[0] : null;
            if (pick) {
                const pair = pypiPickArtifacts(pick[1], pick[1]).find((p) => p.kind === sample.kind);
                const f = await pypiFile(pair.to);
                oldSnap = await snapshotFromArchive('pypi', f.buf, f.filename, sample.kind);
            }
        }
        const newSnap = s.ecosystem === 'npm' ? await npmSnapshot(sample.files) : await pypiSnapshot(sample.files, sample.kind);
        rec.mode = oldSnap ? 'update' : 'new package (no earlier clean version)';
        rec.comparable = sample.gitCheckout ? 'not-an-artifact (git checkout)' : oldSnap ? comparability(oldSnap, newSnap, sample.files) : 'yes';
        const res = diffSnapshots(oldSnap || null, newSnap, { addedPackage: !oldSnap });
        await enrichNewDeps(s.ecosystem, res, s.date ? new Date(s.date).getTime() : Date.now(), await packageOwners(s.ecosystem, s.name));
        rescore(res);
        Object.assign(rec, {
            before, verdict: res.verdict, counts: res.counts,
            highKinds: [...new Set(res.findings.filter((f) => f.severity === 'high').map((f) => f.kind))],
            mediumKinds: [...new Set(res.findings.filter((f) => f.severity === 'medium' && f.category !== 'breaking').map((f) => f.kind))],
            top: res.findings.filter((f) => f.category !== 'breaking').slice(0, 6).map((f) => `${f.severity}: ${f.title}`.slice(0, 200)),
        });
    } catch (e) {
        rec.error = e.message.slice(0, 300);
    }
    rec.ms = Date.now() - t0;
    return rec;
}

const samples = listSamples().filter((s) => !only || splitOf(s.name) === only).slice(0, limit);
const done = new Set();
if (fs.existsSync(outPath)) for (const l of fs.readFileSync(outPath, 'utf8').split('\n').filter(Boolean)) { const r = JSON.parse(l); if (!r.error) done.add(`${r.ecosystem}:${r.name}@${r.version}`); }
const todo = samples.filter((s) => !done.has(`${s.ecosystem}:${s.name}@${s.version}`));
console.error(`${samples.length} samples, ${todo.length} to run`);
let i = 0; let n = 0;
await Promise.all(Array.from({ length: CONC }, async () => {
    while (i < todo.length) {
        const s = todo[i++];
        const r = await runOne(s);
        fs.appendFileSync(outPath, `${JSON.stringify(r)}\n`);
        if (++n % 50 === 0) console.error(`${n}/${todo.length}`);
    }
}));
