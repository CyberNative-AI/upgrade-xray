// Fresh benign updates: the latest stable release vs the one before it (published by 2026-10-01), for the
// most-downloaded PyPI and npm packages not already in benign-bumps.json, in rank order, skipping any package
// the dataset lists as compromised.
//   node fixtures/select-fresh.js DATASET_DIR fixtures/benign-bumps.json OUT.json [N_PYPI 100] [N_NPM 60]
import fs from 'node:fs';
import path from 'node:path';
import semver from 'semver';
import { npmPackument, pypiProject } from '../src/registry.js';
const [dataset, existingPath, outPath, nPy = '100', nNpm = '60'] = process.argv.slice(2);
const existing = new Set(JSON.parse(fs.readFileSync(existingPath, 'utf8')).map((b) => `${b.ecosystem}:${b.name}`));
const mal = { npm: JSON.parse(fs.readFileSync(path.join(dataset, 'samples/npm/manifest.json'))), pypi: JSON.parse(fs.readFileSync(path.join(dataset, 'samples/pypi/manifest.json'))) };
const NOT_AFTER = Date.parse('2026-10-01T00:00:00Z');
async function top(reg, pages) { const out = []; for (let p = 1; p <= pages; p++) { const r = await fetch(`https://packages.ecosyste.ms/api/v1/registries/${reg}/packages?sort=downloads&order=desc&per_page=100&page=${p}`); if (!r.ok) throw new Error(`ecosyste.ms ${reg} page ${p}: HTTP ${r.status}`); for (const x of await r.json()) out.push(x.name); } return out; }
const PRE = /(a|b|rc|alpha|beta|c|pre|preview|dev)\d*$|\.dev|post|[a-z]/i;
const pyParts = (v) => v.split('.').map(Number);
const pyCmp = (a, b) => { const x = pyParts(a), y = pyParts(b); for (let i = 0; i < Math.max(x.length, y.length); i++) if ((x[i] || 0) !== (y[i] || 0)) return (x[i] || 0) - (y[i] || 0); return 0; };
const out = [];
let rank = 0;
for (const name of await top('pypi.org', 3)) {
  rank++; if (out.filter((b) => b.ecosystem === 'pypi').length >= Number(nPy)) break;
  if (existing.has(`pypi:${name}`) || mal.pypi[name] !== undefined) continue;
  try {
    const doc = await pypiProject(name);
    const vs = Object.entries(doc.releases).filter(([v, fs]) => !PRE.test(v) && fs.length && fs.every((f) => !f.yanked) && Date.parse(fs[0].upload_time_iso_8601) <= NOT_AFTER).map(([v]) => v).sort(pyCmp);
    if (vs.length < 2) continue;
    out.push({ ecosystem: 'pypi', name, rank, split: 'fresh', from: vs.at(-2), to: vs.at(-1), published: doc.releases[vs.at(-1)][0].upload_time_iso_8601 });
  } catch (e) { console.error('skip', name, e.message); }
}
rank = 0;
for (const name of await top('npmjs.org', 2)) {
  rank++; if (out.filter((b) => b.ecosystem === 'npm').length >= Number(nNpm)) break;
  if (existing.has(`npm:${name}`) || mal.npm[name] !== undefined) continue;
  try {
    const doc = await npmPackument(name, { full: true });
    const t = doc.time || {};
    const vs = semver.sort(Object.keys(doc.versions || {}).filter((v) => semver.valid(v) && !semver.prerelease(v) && t[v] && Date.parse(t[v]) <= NOT_AFTER));
    if (vs.length < 2) continue;
    out.push({ ecosystem: 'npm', name, rank, split: 'fresh', from: vs.at(-2), to: vs.at(-1), published: t[vs.at(-1)] });
  } catch (e) { console.error('skip', name, e.message); }
}
fs.writeFileSync(outPath, JSON.stringify(out, null, 1));
console.log(out.length, out.filter((b) => b.ecosystem === 'pypi').length, 'pypi');
