// Write the REPORT the Actor would produce for a compromised npm release that the registry no
// longer serves: the bad version comes from a dataset sample, the clean one from the registry.
//   node fixtures/example-report.js NAME CLEAN_VERSION BAD_VERSION RELEASE_DATE SAMPLE.zip OUT.md
import fs from 'node:fs';
import { loadSample } from './sample-reader.js';
import { npmSnapshot } from '../src/snapshot.js';
import { diffSnapshots } from '../src/diff.js';
import { snapshotFromArchive, enrichNewDeps, packageOwners, rescore } from '../src/analyze.js';
import { npmTarball } from '../src/registry.js';
import { runInput } from '../src/main.js';

const [name, before, version, date, zip, out] = process.argv.slice(2);
const kv = {};
const io = {
    pushData: async () => {}, charge: async () => {}, withinLimit: () => Infinity, fail: async (m) => { throw new Error(m); },
    setValue: async (k, v) => { kv[k] = v; },
    analyze: async () => {
        const t = await npmTarball(name, before);
        const oldSnap = await snapshotFromArchive('npm', t.buf, t.filename);
        const newSnap = await npmSnapshot(loadSample(fs.readFileSync(zip), 'npm').files);
        const res = diffSnapshots(oldSnap, newSnap);
        await enrichNewDeps('npm', res, new Date(date).getTime(), await packageOwners('npm', name));
        rescore(res);
        return { ecosystem: 'npm', name, fromVersion: before, toVersion: version, ...res };
    },
};
await runInput({ packages: [`npm:${name}@${before}..${version}`] }, io);
fs.writeFileSync(out, kv.REPORT);
console.log(kv.OUTPUT.verdict);
