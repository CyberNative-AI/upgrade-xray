// Low findings never change a verdict. A "clean" package that lists them is labelled "low notes
// only", never "nothing new found", and the lockfile report's compact list shows the notes.
import test from 'node:test';
import assert from 'node:assert/strict';
import { packageMarkdown, packagesReport, lockfileReport } from '../src/report.js';
import MarkdownIt from 'markdown-it';
import { mark } from '../src/prose.js';
import { built } from './helpers.js';

const md = new MarkdownIt({ html: true, linkify: true });
const mentions = (m) => md.render(m).replace(/<(code|pre|a)\b[^>]*>[\s\S]*?<\/\1>/gi, ' ').replace(/<[^>]*>/g, ' ').match(/(?:^|[^A-Za-z0-9_])@[A-Za-z0-9][\w-]*/g) || [];

const low = (detail, file = 'm/compat.py') => built({ severity: 'low', category: 'security', kind: 'dynamic-require', title: `New: loads a module whose name is computed at run time — ${mark(detail)}`, detail, locations: [{ file, line: 24 }] });
const pkg = (name, findings = []) => ({ ecosystem: 'npm', name, fromVersion: '1.0.0', toVersion: '1.0.1', verdict: 'clean', coverage: { complete: true }, findings, files: { added: 0, changed: 1, removed: 0, total: 1 } });
const diff = { type: 'npm', updated: [{}, {}], added: [], removed: [], nonRegistry: [] };

test('a clean package with low findings is not headed "nothing new found"', () => {
    const out = packageMarkdown(pkg('a', [low('importlib.import_module(<computed>)')]));
    assert.match(out, /^### 🟢 LOW NOTES ONLY — `a` `1\.0\.0` → `1\.0\.1` \(npm\)$/m);
    assert.doesNotMatch(out, /NOTHING NEW FOUND/);
    assert.match(packageMarkdown(pkg('b')), /^### 🟢 NOTHING NEW FOUND — /m);
});

test('package mode: overall and counts split low notes from nothing new', () => {
    const out = packagesReport([pkg('a', [low('x()')]), pkg('b')], { verdict: 'clean', coverage: { complete: true } });
    assert.match(out, /\*\*Overall: 🟢 Nothing needing review; low notes only\*\*/);
    assert.match(out, /\*\*0 to review · 0 worth a look · 1 nothing new · 1 low notes only\*\*/);
    assert.doesNotMatch(out, /Nothing new found in any change/);
    assert.match(packagesReport([pkg('b')], { verdict: 'clean', coverage: { complete: true } }), /Overall: 🟢 Nothing new found in any change/);
});

test('lockfile mode: the compact list names its low notes instead of hiding them', () => {
    const out = lockfileReport([pkg('a', [low('x()'), low('y()')]), pkg('b')], diff, { verdict: 'clean', coverage: { complete: true } });
    assert.match(out, /<summary>Nothing needing review in 2 package\(s\); 1 with low notes<\/summary>/);
    assert.match(out, /^- `a` `1\.0\.0` → `1\.0\.1` \(npm\)\n {2}- \*\*Low\*\* New: loads a module whose name is computed at run time: `x\(\)`, `y\(\)` · in `m\/compat\.py:24`$/m);
    assert.match(lockfileReport([pkg('b')], diff, { verdict: 'clean', coverage: { complete: true } }), /<summary>Nothing new found in 1 package\(s\)<\/summary>/);
});

test('low notes in the compact list stay inert', () => {
    const bad = ['`@victim', '@one@two', '<b>@i</b>', '[t](u`rl) @j'];
    const out = lockfileReport([pkg('@s/a', bad.map((d) => low(d, `@x/${d}`)))], diff, { verdict: 'clean', coverage: { complete: true } });
    assert.deepEqual(mentions(out), [], out);
});
