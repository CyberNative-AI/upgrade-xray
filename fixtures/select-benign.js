// Pick benign major-version bumps systematically: walk the most-downloaded npm and PyPI
// packages (ecosyste.ms ranking) and take each one's latest major bump.
//   node fixtures/select-benign.js DATASET_DIR OUT.json [--per-split-npm 50] [--per-split-pypi 50]
import fs from 'node:fs';
import path from 'node:path';
import semver from 'semver';
import { npmPackument, pypiProject } from '../src/registry.js';
import { splitOf } from './split.js';

const [dataset, outPath, ...rest] = process.argv.slice(2);
const arg = (k, d) => (rest.includes(k) ? Number(rest[rest.indexOf(k) + 1]) : d);
const WANT = { npm: { holdout: arg('--per-split-npm', 50), dev: 25 }, pypi: { holdout: arg('--per-split-pypi', 50), dev: 25 } };
const NOT_AFTER = new Date('2026-10-01T00:00:00Z').getTime(); // leave time for a compromise to be found
const NOT_BEFORE = new Date('2021-10-01T00:00:00Z').getTime();

const manifests = {
    npm: JSON.parse(fs.readFileSync(path.join(dataset, 'samples/npm/manifest.json'), 'utf8')),
    pypi: JSON.parse(fs.readFileSync(path.join(dataset, 'samples/pypi/manifest.json'), 'utf8')),
};

async function top(registry, pages) {
    const names = [];
    for (let p = 1; p <= pages; p++) {
        const res = await fetch(`https://packages.ecosyste.ms/api/v1/registries/${registry}/packages?sort=downloads&order=desc&per_page=100&page=${p}`);
        for (const x of await res.json()) names.push(x.name);
    }
    return names;
}

const PRE = /(a|b|rc|alpha|beta|c|pre|preview|dev)\d*|\.dev|post/i;
const pyKey = (v) => { const m = v.match(/^(\d+)\.(\d+)/); return m ? (m[1] === '0' ? `0.${m[2]}` : m[1]) : null; };
const pyParts = (v) => v.split(/[.]/).map((x) => (/^\d+$/.test(x) ? Number(x) : 0));
const pyCmp = (a, b) => { const x = pyParts(a); const y = pyParts(b); for (let i = 0; i < Math.max(x.length, y.length); i++) if ((x[i] || 0) !== (y[i] || 0)) return (x[i] || 0) - (y[i] || 0); return 0; };

async function npmBump(name) {
    const doc = await npmPackument(name, { full: true });
    const time = doc.time || {};
    const vers = Object.keys(doc.versions || {}).filter((v) => semver.valid(v) && !semver.prerelease(v) && time[v] && new Date(time[v]).getTime() <= NOT_AFTER);
    const group = (v) => (semver.major(v) === 0 ? `0.${semver.minor(v)}` : String(semver.major(v)));
    const sorted = semver.sort(vers);
    const groups = [...new Set(sorted.map(group))];
    for (let g = groups.length - 1; g >= 1; g--) {
        const first = sorted.find((v) => group(v) === groups[g]);
        const prev = sorted.filter((v) => group(v) === groups[g - 1]).pop();
        if (new Date(time[first]).getTime() < NOT_BEFORE) return null;
        if (manifests.npm[name] === null || (manifests.npm[name] || []).includes(first)) return null;
        return { from: prev, to: first, published: time[first] };
    }
    return null;
}

async function pypiBump(name) {
    const doc = await pypiProject(name);
    const rel = Object.entries(doc.releases || {}).filter(([v, files]) => files.length && !PRE.test(v) && pyKey(v) && !files.every((f) => f.yanked));
    const t = (files) => Math.min(...files.map((f) => new Date(f.upload_time_iso_8601).getTime()));
    const ok = rel.filter(([, files]) => t(files) <= NOT_AFTER).sort((a, b) => pyCmp(a[0], b[0]));
    const groups = [...new Set(ok.map(([v]) => pyKey(v)))];
    for (let g = groups.length - 1; g >= 1; g--) {
        const first = ok.find(([v]) => pyKey(v) === groups[g]);
        const prev = ok.filter(([v]) => pyKey(v) === groups[g - 1]).pop();
        if (!first || !prev) return null;
        if (t(first[1]) < NOT_BEFORE) return null;
        if (manifests.pypi[name] === null || (manifests.pypi[name] || []).includes(first[0])) return null;
        return { from: prev[0], to: first[0], published: new Date(t(first[1])).toISOString() };
    }
    return null;
}

const out = [];
for (const [eco, registry, fn] of [['npm', 'npmjs.org', npmBump], ['pypi', 'pypi.org', pypiBump]]) {
    const names = await top(registry, 5);
    const have = { dev: 0, holdout: 0 };
    let rank = 0;
    for (const name of names) {
        rank++;
        const split = splitOf(name);
        if (have[split] >= WANT[eco][split]) { if (have.dev >= WANT[eco].dev && have.holdout >= WANT[eco].holdout) break; continue; }
        try {
            const b = await fn(name);
            if (!b) continue;
            out.push({ ecosystem: eco, name, rank, split, ...b });
            have[split]++;
        } catch (e) {
            console.error(`${eco}:${name}: ${e.message}`);
        }
    }
    console.error(eco, have);
}
fs.writeFileSync(outPath, `${JSON.stringify(out, null, 1)}\n`);
