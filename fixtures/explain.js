// Print Upgrade X-Ray findings (with locations) for one dataset sample vs a clean version.
//   node fixtures/explain.js npm|pypi NAME CLEAN_VERSION SAMPLE.zip
import fs from 'node:fs';
import { loadSample } from './sample-reader.js';
import { npmSnapshot, pypiSnapshot } from '../src/snapshot.js';
import { diffSnapshots } from '../src/diff.js';
import { snapshotFromArchive } from '../src/analyze.js';
import { npmTarball, pypiProject, pypiPickArtifacts, pypiFile } from '../src/registry.js';

const [eco, name, before, zip] = process.argv.slice(2);
const sample = loadSample(fs.readFileSync(zip), eco);
let oldSnap;
if (eco === 'npm') { const t = await npmTarball(name, before); oldSnap = await snapshotFromArchive('npm', t.buf, t.filename); }
else {
    const doc = await pypiProject(name);
    const pair = pypiPickArtifacts(doc.releases[before], doc.releases[before]).find((p) => p.kind === sample.kind);
    const f = await pypiFile(pair.to);
    oldSnap = await snapshotFromArchive('pypi', f.buf, f.filename, sample.kind);
}
const newSnap = eco === 'npm' ? await npmSnapshot(sample.files) : await pypiSnapshot(sample.files, sample.kind);
const r = diffSnapshots(oldSnap, newSnap);
console.log(r.verdict, r.files);
for (const f of r.findings) console.log(`${f.severity}\t${f.title}\t${(f.locations || []).map((l) => `${l.file}:${l.line}`).join(' ')}`);
