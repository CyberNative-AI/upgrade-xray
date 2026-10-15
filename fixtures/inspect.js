// Show which files differ between the clean previous version and a sample, with a short
// look at the largest additions. Analysis aid only: prints text, runs nothing.
import fs from 'node:fs';
import { loadSample } from './sample-reader.js';
import { npmTarball, pypiProject, pypiPickArtifacts, pypiFile } from '../src/registry.js';
import { readArchive, stripCommonRoot } from '../src/archive.js';

const [eco, name, before, zip, focus] = process.argv.slice(2);
const sample = loadSample(fs.readFileSync(zip), eco);
let old;
if (eco === 'npm') old = stripCommonRoot(readArchive((await npmTarball(name, before)).buf, 'x.tgz'));
else {
    const doc = await pypiProject(name);
    const pair = pypiPickArtifacts(doc.releases[before], doc.releases[before]).find((p) => p.kind === sample.kind);
    const f = await pypiFile(pair.to);
    old = stripCommonRoot(readArchive(f.buf, f.filename));
}
for (const [p, b] of sample.files) {
    const o = old.get(p);
    if (o && o.equals(b)) continue;
    const t = b.toString('utf8');
    console.log(`${o ? 'CHANGED' : 'ADDED  '} ${p} ${o ? o.length : 0} -> ${b.length}`);
    if (focus && p.includes(focus)) {
        const ot = o ? o.toString('utf8') : '';
        // print the part of the new file that is not in the old (rough tail/line diff)
        const oldLines = new Set(ot.split('\n'));
        const add = t.split('\n').filter((l) => !oldLines.has(l));
        for (const l of add.slice(0, 15)) console.log('   + ' + (l.length > 400 ? `${l.slice(0, 200).replace(/^\s+/, (m) => `[${m.length} spaces]`)} … [${l.length} chars]` : l));
    }
}
