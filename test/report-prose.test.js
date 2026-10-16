// Finding titles, notes, versions and errors are prose built around package data: file and module
// names, dependency names and specs, export and command names, engine ranges, error messages.
// Rendered, none of it may become a link, an issue reference, HTML, a heading, emphasis or a
// mention, including links a repository defines itself (custom autolink prefixes, which can match
// any word, so no check of what a value contains can be complete).
//
// The report shows text only where the tool wrote it: a title or note template whose package
// values are marked, carried under a Symbol key by the object the tool built. Everything else is
// code. These tests check that boundary on the rendered HTML, through the real snapshot, diff and
// merge path, and read the templates in src/ so that a new interpolation cannot skip v().
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import * as acorn from 'acorn';
import * as walk from 'acorn-walk';
import MarkdownIt from 'markdown-it';
import { diffSnapshots } from '../src/diff.js';
import { mergeArtifactResults } from '../src/analyze.js';
import { readZip } from '../src/archive.js';
import { pypiSnapshot } from '../src/snapshot.js';
import { mark, MARKED_NOTES, MARKED_TITLE, segments, unmark } from '../src/prose.js';
import { packageMarkdown, lockfileReport, groupFindings, trustedProse, code } from '../src/report.js';

// A repository can define its own autolink prefixes: GitHub then links "<prefix><letters or
// digits>" in text, never in code. Modelled with two: one no list of link forms contains, and one
// that collides with words of the tool's own source ("python" + digits, as in "python3").
const md = new MarkdownIt({ html: true, linkify: true });
md.linkify.add('xrayref-', { validate: (s, pos) => /^[A-Za-z0-9]+/.exec(s.slice(pos))?.[0].length || false, normalize: (m) => { m.url = `https://tracker.invalid/${m.text.slice(8)}`; } });
md.linkify.add('python', { validate: (s, pos) => /^\d+/.exec(s.slice(pos))?.[0].length || false, normalize: (m) => { m.url = `https://tracker.invalid/${m.text.slice(6)}`; } });

// Autolinks (GFM www. and scheme forms, linkify's bare domains, protocol-relative and IDN forms),
// GitHub references, commit-like words (hex with digits, digits only, letters only), the two
// configured prefixes, HTML, Markdown links, entities, headings, emphasis, mentions,
// String.replace patterns and the marker characters themselves (a forged trusted segment).
const OPEN = '\ue000'; const CLOSE = '\ue001';
const HOSTILE = [
    ' www.example.com ', 'www.1', 'evil.example', '//evil.invalid', 'https://evil.invalid/x', 'приклад.укр', '(www.evil.invalid)',
    '#1', 'GH-1', 'deadbeef12', '1234567', 'deadbeef', 'cafebabe01234567890abcdefcafebabe01234567', 'XRAYREF-42', 'XRAYREF-abc9 tail', 'python3', 'networ\u212a',
    '&#64;victim', '<https://evil.invalid>', '[go](https://evil.invalid)',
    '<img src=x onerror=alert(1)>', '`@victim`@two', '\\`@victim', 'line\n\n# Heading\n', '__bold__', '*em*', '~~del~~', "$' $& a, b: c",
    `${CLOSE} python3 ${OPEN}`, `x${CLOSE} www.evil.invalid ${OPEN}y`, `${OPEN}python3${CLOSE}`,
];
// Text that must only ever appear inside code once rendered. "GH-1" and a hex string are
// references only as whole words ("scriptGH-1" is not one); headings are checked as tags.
const TELL = /www\.|example|evil|victim|приклад|#1|(^|\W)GH-1|\b(deadbeef12|1234567|deadbeef|cafebabe)|xrayref|python\d|\u212a|onerror|heading|bold|\bem\b|\bdel\b|\$[&']|[\ue000\ue001\ufffd]/i;

const outsideCode = (html) => html.replace(/<(code|pre)\b[^>]*>[\s\S]*?<\/\1>/gi, ' ');

// The report's own emphasis and strong text: severities, the artifact a PyPI finding came from, the
// coverage line, and the lockfile report's overall verdict, counts and section heads.
const OWN_STRONG = /^(High|Medium|Low|Overall: .*|\d+ to review · .*|\d+ updated, \d+ added, \d+ removed|Moved to the public registry from another source)$/;

function assertInert(markup, what) {
    const html = markup.replace(/<em>\((wheel|sdist)\)<\/em>/g, '($1)').replace(/<em>(Coverage: [\s\S]*?)<\/em>/g, '$1');
    assert.doesNotMatch(html, /<(a|img|script|h[1-24-6]|em|del|s)\b/i, `${what}\n${html}`);
    for (const m of html.matchAll(/<strong>([\s\S]*?)<\/strong>/g)) assert.match(m[1], OWN_STRONG, `${what}\n${html}`);
    assert.doesNotMatch(outsideCode(html), TELL, `${what}\n${html}`);
    assert.doesNotMatch(outsideCode(html), /@/, `${what}\n${html}`);
}

test('the oracle is not vacuous: every hostile value is caught as text, and the prefix models link only text', () => {
    for (const h of HOSTILE) assert.match(h, TELL, JSON.stringify(h));
    for (const [w, n] of [['XRAYREF-42', '42'], ['python3', '3']]) {
        assert.match(md.render(`- Removed module: ${w}`), new RegExp(`<a href="https://tracker\\.invalid/${n}">${w}</a>`));
        assert.doesNotMatch(md.render(`- Removed module: ${code(w)}`), /<a\b/);
    }
});

const snap = (ecosystem, s) => ({ ecosystem, files: new Map(), signals: [], installScripts: {}, installFiles: new Set(), deps: {}, api: {}, meta: {}, notes: [], ...s });
const files = (hash, ...names) => new Map(names.map((f) => [f, { hash: f.startsWith('same') ? 'same' : hash }]));
const api = (names, source = []) => ({ names: new Set(names), resolved: true, source });

/** An old and a new snapshot whose differences reach every title template, all carrying h. */
function pair(ecosystem, h) {
    const changedFile = `${h}.js`; const capFile = `inst${h}.js`; const perFile = `lib/${h}.js`;
    const all = ['same.js', changedFile, capFile, perFile];
    const old = snap(ecosystem, {
        files: files('old', ...all),
        installScripts: { [`script${h}`]: 'a', [`gone${h}`]: 'x' },
        installFiles: new Set([changedFile, capFile]),
        signals: [{ file: 'same.js', kind: 'credential-path', detail: '/.npmrc', line: 1 }],
        deps: { [`old${h}`]: { spec: '1', field: 'dependencies' }, [`src${h}`]: { spec: '1.0.0', field: 'dependencies' } },
        api: { [`./sub${h}`]: api(['a', 'b', `x${h}`]), [`./gone${h}`]: api(['a']), [`./und${h}`]: api(['a']) },
        meta: { engines: `>=1 ${h}`, bin: { [`old${h}`]: 'x' }, requiresPython: `>=3.8 ${h}` },
    });
    const neu = snap(ecosystem, {
        files: files('new', ...all),
        installScripts: { [`script${h}`]: 'b', [`new${h}`]: 'c' },
        installFiles: new Set([changedFile, capFile]),
        signals: [
            ...old.signals,
            { file: capFile, kind: 'network', detail: `fetch ${h}`, line: 2 },
            { file: perFile, kind: 'credential-path', detail: '/.npmrc', line: 3 },
            { file: 'x.js', kind: 'new-host', detail: h, line: 4 },
            { file: 'y.js', kind: 'minified-blob', detail: h, line: 0 },
            // A kind the tool has no label for is shown as a value.
            { file: 'z.js', kind: `kind${h}`, detail: h, line: 5 },
        ],
        deps: { [`dep${h}`]: { spec: h, field: 'dependencies' }, [`src${h}`]: { spec: `https://${h}`, field: 'dependencies' } },
        api: { [`./sub${h}`]: api(['a', 'b'], [`${h}.js`]), [`./und${h}`]: { ...api([]), resolved: false } },
        meta: { name: `pkg${h}`, exportsKeys: [`./sub${h}`, `./und${h}`], engines: `>=2 ${h}`, bin: { [`new${h}`]: h }, requiresPython: `>=3.9 ${h}` },
        // Notes added without the tool's builder carry no marked form.
        notes: [`${h} skipped (encrypted)`],
    });
    return [old, neu];
}

// Kinds whose title template in src/diff.js interpolates a value, read from the source itself so a
// new template cannot be added without this test reaching it.
const TEMPLATE_KINDS = new Set([...readFileSync(new URL('../src/diff.js', import.meta.url), 'utf8').matchAll(/kind: '([a-z-]+)', title: `[^`]*\$\{/g)].map((m) => m[1]));

test('every title built from package data renders as plain text and code, never as a link or markup', () => {
    assert.ok(TEMPLATE_KINDS.size >= 15, [...TEMPLATE_KINDS].join(', '));
    const reached = new Set();
    for (const h of HOSTILE) {
        for (const ecosystem of ['npm', 'pypi']) {
            const [old, neu] = pair(ecosystem, h);
            const results = [diffSnapshots(old, neu), diffSnapshots(null, neu, { addedPackage: true })];
            // PyPI findings reach the report through the wheel/sdist merge, which copies each finding.
            if (ecosystem === 'pypi') results.push(...results.map((result) => mergeArtifactResults([{ kind: 'wheel', result }])));
            for (const r of results) {
                for (const f of r.findings) reached.add(f.kind);
                // "New in <file>" (per file), "New:" and "Has:" (new package) signal titles.
                for (const head of ['New in ', 'New: ', 'Has: ']) if (r.findings.some((f) => f.title.startsWith(head))) reached.add(head);
                const html = md.render(packageMarkdown({ ecosystem, name: 'pkg', fromVersion: `1.0 ${h}`, toVersion: `1.1 ${h}`, ...r }, { maxFindings: 100 }));
                assertInert(html, `${ecosystem} ${JSON.stringify(h)}`);
                assert.equal(html.match(/<h3\b/g).length, 1, html);
            }
        }
    }
    for (const kind of [...TEMPLATE_KINDS, 'network', 'credential-path', 'New in ', 'New: ', 'Has: ']) assert.ok(reached.has(kind), `not reached: ${kind}`);
});

/** A wheel holding one encrypted entry named `name`: readZip records it, nothing is decrypted or run. */
function encryptedWheel(name) {
    const n = Buffer.from(name, 'utf8');
    const cd = Buffer.alloc(46); cd.writeUInt32LE(0x02014b50); cd.writeUInt16LE(0x801, 8); cd.writeUInt16LE(n.length, 28);
    const eo = Buffer.alloc(22); eo.writeUInt32LE(0x06054b50); eo.writeUInt16LE(1, 8); eo.writeUInt16LE(1, 10); eo.writeUInt32LE(cd.length + n.length, 12);
    return Buffer.concat([cd, n, eo]);
}

test('a note naming a package file renders the file as code, through readZip, the snapshot, the diff and the merge', async () => {
    for (const h of HOSTILE) {
        const name = `pkg/${h.trim()}`;
        const s = await pypiSnapshot(readZip(encryptedWheel(name)), 'wheel');
        assert.equal(s.notes.length, 1, name);
        assert.match(s.notes[0], / skipped \(encrypted\)$/);
        // The sdist has a note of its own, so its marked form must survive the merge itself.
        const sd = await pypiSnapshot(readZip(encryptedWheel(`sd/${h.trim()}`)), 'sdist');
        for (const result of [diffSnapshots(null, s, { addedPackage: true }), diffSnapshots(s, s)]) {
            const merged = mergeArtifactResults([{ kind: 'wheel', result }, { kind: 'sdist', result: diffSnapshots(null, sd, { addedPackage: true }) }]);
            // analyze.js adds the message of an artifact that failed to the notes: not the tool's prose.
            merged.notes.push(`sdist: ${h}`);
            for (const [r, notes] of [[result, 1], [merged, 2]]) {
                const html = md.render(packageMarkdown({ ecosystem: 'pypi', name: 'pkg', toVersion: '1', ...r }));
                assertInert(html, JSON.stringify(h));
                // Every note starts with a code span; "<" inside one is always escaped.
                const shown = html.match(/Notes: (.*)<\/sub>/)[1].split(/; (?=<code>)/);
                assert.equal(shown.length, r.notes.length, html);
                for (const n of shown.slice(0, notes)) assert.match(n, /^<code>[^<]*<\/code> skipped \(encrypted\)$/, html);
                if (r === merged) assert.match(shown[2], /^<code>sdist: [^<]*<\/code>$/, html);
            }
        }
    }
    // The case Security reported: "python3" matched the tool's own words and rendered as a link.
    const s = await pypiSnapshot(readZip(encryptedWheel('python3')), 'wheel');
    const html = md.render(packageMarkdown({ ecosystem: 'pypi', name: 'pkg', toVersion: '1', ...diffSnapshots(null, s, { addedPackage: true }) }));
    assert.match(html, /Notes: <code>python3<\/code> skipped \(encrypted\)/);
    assert.doesNotMatch(html, /<a\b/);
});

test('errors, origins and other untrusted text render whole as code, marker characters included', () => {
    for (const h of HOSTILE) {
        for (const s of [h, `before ${h} after`, `(${h})`, `${h}.`, `${h}, next`, `a:${h}`, `Removed module: ${OPEN}x${CLOSE} ${h}`]) {
            const err = md.render(packageMarkdown({ ecosystem: 'npm', name: 'pkg', toVersion: s, error: s }));
            assertInert(err, JSON.stringify(s));
            assert.match(err, /<p>Could not analyse: <code>[^<]*<\/code><\/p>/, err);
            assertInert(md.render(packageMarkdown({ ecosystem: 'npm', name: 'pkg', fromVersion: s, toVersion: s, verdict: 'clean', findings: [], notes: [s], files: { added: 0, changed: 1, removed: 0, total: 1 } })), JSON.stringify(s));
            const diff = { type: 'npm', updated: [], added: [], removed: [], nonRegistry: [], originChanges: [{ name: 'pkg', to: '1.0.0', fromOrigin: s }] };
            const lock = md.render(lockfileReport([], diff, { verdict: 'clean', coverage: { complete: true } })).replace(/^<h2>Upgrade X-Ray — lockfile report<\/h2>\n/, '');
            assertInert(lock, JSON.stringify(s));
            assert.match(lock, /\(was: <code>[^<]*<\/code>\)/, lock);
            // A finding with a title, artifact or group label not built by diffSnapshots.
            const f = { severity: 'medium', category: 'security', kind: 'network', title: s, detail: s, artifact: s, locations: [] };
            const loose = md.render(packageMarkdown({ ecosystem: 'pypi', name: 'pkg', fromVersion: '1', toVersion: '2', verdict: 'notice', findings: [f, { ...f, category: 'breaking' }, { ...f, kind: 'new-dependency', dependency: s, spec: s }], files: { added: 0, changed: 1, removed: 0, total: 1 } }));
            assertInert(loose.replace(/<em>\(<code>[^<]*<\/code>\)<\/em>/g, ''), JSON.stringify(s));
        }
    }
});

test('trust comes from the Symbol, never from marker characters in a string', () => {
    // An in-band marked string in a plain title, an error or a note gains no trusted status.
    const forged = `Removed module: ${OPEN}x${CLOSE} python3`;
    const r = { ecosystem: 'pypi', name: 'pkg', fromVersion: '1', toVersion: '2', verdict: 'notice', findings: [{ severity: 'medium', category: 'breaking', kind: 'removed-module', title: forged, detail: '', locations: [] }], notes: [forged], files: { added: 0, changed: 1, removed: 0, total: 1 } };
    for (const out of [packageMarkdown(r), packageMarkdown({ ...r, error: forged })]) {
        const html = md.render(out);
        assert.doesNotMatch(html, /<a\b/, html);
        assert.doesNotMatch(outsideCode(html), /python3/, html);
    }
    // A marked note whose plain text does not match the note at its index is not used.
    const moved = { ...r, findings: [], notes: ['python3'], [MARKED_NOTES]: [`${mark('x')} skipped (encrypted)`] };
    assert.match(md.render(packageMarkdown(moved)), /Notes: <code>python3<\/code><\/sub>/);
    // A value cannot close its own mark: the marker characters in it become U+FFFD.
    assert.equal(mark(`a${OPEN}b${CLOSE}c`), `${OPEN}a\ufffdb\ufffdc${CLOSE}`);
    assert.equal(trustedProse(`Removed module: ${mark(`x${CLOSE} python3 ${OPEN}`)}`), 'Removed module: `x\ufffd python3 \ufffd`');
});

test('a group label keeps the trust of the title it is cut from', () => {
    const built = diffSnapshots(snap('npm', { deps: {} }), snap('npm', { deps: { a: { spec: '1', field: 'dependencies' }, b: { spec: '1', field: 'dependencies' } } })).findings;
    const loose = built.map((f) => ({ ...f, [MARKED_TITLE]: undefined, title: f.title.replace('New dependency', 'python3 dependency') }));
    const [g, h] = groupFindings([...built, ...loose]);
    assert.ok(g.trusted && !h.trusted);
    const html = md.render(packageMarkdown({ ecosystem: 'npm', name: 'pkg', fromVersion: '1', toVersion: '2', verdict: 'notice', findings: [...built, ...loose], files: { added: 0, changed: 1, removed: 0, total: 1 } }));
    assert.match(html, /<li><strong>Medium<\/strong> New dependencies \(2\): <code>a<\/code> <code>1<\/code>, <code>b<\/code> <code>1<\/code>/, html);
    assert.match(html, /<li><strong>Medium<\/strong> <code>python3 dependency<\/code>: /, html);
    assert.doesNotMatch(html, /<a\b/);
});

test('JSON keeps plain titles and notes; only the report sees the marked forms', () => {
    for (const ecosystem of ['npm', 'pypi']) {
        const [o, n] = pair(ecosystem, 'XRAYREF-42');
        n.notes = []; n[MARKED_NOTES] = [];
        n.notes.push('x'); // a note added directly: no marked form, kept in place
        for (const r of [diffSnapshots(o, n), diffSnapshots(null, n, { addedPackage: true })]) {
            assert.doesNotMatch(JSON.stringify(r), /[\ue000\ue001]/u);
            for (const f of r.findings) {
                assert.equal(typeof f[MARKED_TITLE], 'string', f.title);
                assert.equal(unmark(f[MARKED_TITLE]), f.title);
                // Every template marks every package value it interpolates: none is left in the fixed text.
                assert.doesNotMatch(segments(f[MARKED_TITLE]).filter((_, i) => i % 2 === 0).join(''), /XRAYREF/, `${f.kind}: ${f.title}`);
            }
            assert.deepEqual(r.notes, ['x']);
            assert.equal(r[MARKED_NOTES][0], undefined);
        }
    }
});

test('ordinary prose stays plain; package values read as code', () => {
    const [o, n] = pair('npm', 'q');
    const titles = [...diffSnapshots(o, n).findings, ...diffSnapshots(null, n, { addedPackage: true }).findings].map((f) => trustedProse(f[MARKED_TITLE]));
    for (const t of ['Install-time file changed: `q.js`', 'Removed command(s): `oldq`', 'New command(s) on PATH: `newq`', 'Node engine requirement: `>=1 q` → `>=2 q`', 'Install-time script removed: `goneq`', 'Removed import path: `pkgq/goneq`']) assert.ok(titles.includes(t), `${t}\n${titles.join('\n')}`);
    assert.ok(titles.includes('Code that runs at install or start-up gained: network access'), titles.join('\n'));
    assert.ok(titles.includes('New: `kindq` — `q`'), titles.join('\n'));
    // Markdown characters in the tool's own text are escaped, so they read as written.
    assert.equal(trustedProse(`New: starts a process — ${mark('subprocess.run')} (in a package __init__, runs on import)`), 'New: starts a process — `subprocess.run` (in a package \\_\\_init\\_\\_, runs on import)');
    assert.match(md.render(`- ${trustedProse('(in a package __init__, runs on import)')}`), /<li>\(in a package __init__, runs on import\)<\/li>/);
});

// --- The templates themselves --------------------------------------------------------------
// In a title or note template, an interpolation is a package value only through v(). Anything
// else must be a named tool constant, a count, a fixed string, or a choice between those.
const TOOL_CALLS = new Set(['kindLabel', 'kindLabels']);
const TOOL_NAMES = new Set(['scriptNote']);
function count(n) {
    if (n.type === 'Literal') return typeof n.value === 'number';
    if (n.type === 'MemberExpression') return !n.computed && n.property.name === 'length';
    if (n.type === 'BinaryExpression') return ['+', '-'].includes(n.operator) && count(n.left) && count(n.right);
    return false;
}
function allowed(n) {
    switch (n.type) {
        case 'TemplateLiteral': return n.expressions.every(allowed);
        case 'Literal': return typeof n.value === 'string';
        case 'ConditionalExpression': return allowed(n.consequent) && allowed(n.alternate);
        case 'Identifier': return TOOL_NAMES.has(n.name);
        case 'CallExpression': {
            if (n.callee.type === 'Identifier') return n.callee.name === 'v' || TOOL_CALLS.has(n.callee.name);
            // list.map(v).join(', ')
            const c = n.callee;
            return c.type === 'MemberExpression' && c.property.name === 'join' && n.arguments.every((a) => a.type === 'Literal')
                && c.object.type === 'CallExpression' && c.object.callee.property?.name === 'map' && c.object.arguments.length === 1 && c.object.arguments[0].name === 'v';
        }
        default: return count(n);
    }
}
const parse = (file) => acorn.parse(readFileSync(new URL(`../src/${file}`, import.meta.url), 'utf8'), { ecmaVersion: 'latest', sourceType: 'module' });

/** Title templates in diff.js (every add() argument's title) and note templates in snapshot.js. */
function templates({ diff = parse('diff.js'), snapshot = parse('snapshot.js') } = {}) {
    const out = [];
    walk.simple(diff, {
        CallExpression(n) {
            if (n.callee.name !== 'add') return;
            const title = n.arguments[0]?.properties?.find((p) => p.key?.name === 'title');
            out.push({ where: `diff.js:${n.start}`, node: title?.value ?? n });
        },
    });
    walk.simple(snapshot, { CallExpression(n) { if (n.callee.name === 'addNote') out.push({ where: `snapshot.js:${n.start}`, node: n.arguments[1] ?? n }); } });
    return out;
}

test('every interpolation in a title or note template is a marked value or a tool constant', () => {
    const found = templates();
    assert.ok(found.filter((t) => t.where.startsWith('diff')).length >= 20, found.length);
    assert.ok(found.filter((t) => t.where.startsWith('snapshot')).length >= 6, found.length);
    for (const t of found) assert.ok(allowed(t.node), `${t.where}: ${t.node.type}`);
    // Findings and notes are only made through those builders.
    const src = (f) => readFileSync(new URL(`../src/${f}`, import.meta.url), 'utf8');
    assert.equal(src('diff.js').match(/findings\.push\(/g).length, 1);
    assert.doesNotMatch(src('snapshot.js'), /notes\.push\(/);
    // The check itself: an unlisted interpolation fails it.
    const bad = acorn.parse('add({ title: `Removed module: ${sub}` }); add({ title: `x ${v(a)} ${b.name}` }); add({ title: `${xs.map(String).join(", ")}` });', { ecmaVersion: 'latest' });
    assert.deepEqual(templates({ diff: bad, snapshot: acorn.parse('addNote(snap, `${p} skipped`)', { ecmaVersion: 'latest' }) }).map((t) => allowed(t.node)), [false, false, false, false]);
});

test('long hostile values render in linear time', () => {
    for (const w of [`#${','.repeat(200000)}x`, `(${'a.b'.repeat(100000)})`, `${'deadbeef1-'.repeat(50000)}`, `${OPEN}${CLOSE}`.repeat(100000)]) {
        const t = process.hrtime.bigint();
        trustedProse(`Removed module: ${mark(w)}`);
        packageMarkdown({ ecosystem: 'npm', name: 'pkg', error: w });
        assert.ok(process.hrtime.bigint() - t < 500_000_000n, `${w.slice(0, 20)}… took ${(process.hrtime.bigint() - t) / 1_000_000n} ms`);
    }
});
