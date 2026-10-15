// Run Upgrade X-Ray over the selected benign major bumps (real registry downloads).
//   node fixtures/run-benign.js benign-bumps.json OUT.jsonl [--only dev|holdout]
import fs from 'node:fs';
import { analyzePackage } from '../src/analyze.js';

const [listPath, outPath, ...rest] = process.argv.slice(2);
const only = rest.includes('--only') ? rest[rest.indexOf('--only') + 1] : null;
const list = JSON.parse(fs.readFileSync(listPath, 'utf8')).filter((b) => !only || b.split === only);
const done = new Set(fs.existsSync(outPath) ? fs.readFileSync(outPath, 'utf8').split('\n').filter(Boolean).map((l) => { const r = JSON.parse(l); return r.error ? null : `${r.ecosystem}:${r.name}`; }) : []);
const todo = list.filter((b) => !done.has(`${b.ecosystem}:${b.name}`));
console.error(`${list.length} bumps, ${todo.length} to run`);
let i = 0;
await Promise.all(Array.from({ length: 4 }, async () => {
    while (i < todo.length) {
        const b = todo[i++];
        const rec = { ecosystem: b.ecosystem, name: b.name, from: b.from, to: b.to, rank: b.rank, split: b.split };
        try {
            const r = await analyzePackage({ ecosystem: b.ecosystem, name: b.name, from: b.from, to: b.to });
            Object.assign(rec, {
                verdict: r.verdict, counts: r.counts, breaking: r.breaking, ms: r.analysisMs,
                highKinds: [...new Set(r.findings.filter((f) => f.severity === 'high').map((f) => f.kind))],
                top: r.findings.filter((f) => f.category !== 'breaking').slice(0, 6).map((f) => `${f.severity}: ${f.title}${f.locations?.[0] ? ` @ ${f.locations[0].file}:${f.locations[0].line}` : ''}`.slice(0, 240)),
            });
        } catch (e) { rec.error = e.message.slice(0, 300); }
        fs.appendFileSync(outPath, `${JSON.stringify(rec)}\n`);
    }
}));
