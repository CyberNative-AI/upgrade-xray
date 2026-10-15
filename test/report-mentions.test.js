// Reports are posted as pull-request comments: npm scopes must not become @mentions there.
import test from 'node:test';
import assert from 'node:assert/strict';
import { runInput } from '../src/main.js';
import { quoteMentions } from '../src/report.js';
import { memoryIo } from './helpers.js';

const pub = (n, v) => ({ version: v, resolved: `https://registry.npmjs.org/${n}/-/${n.split('/').pop()}-${v}.tgz` });
const lock = (pkgs) => JSON.stringify({ lockfileVersion: 3, packages: { '': {}, ...Object.fromEntries(Object.entries(pkgs).map(([k, v]) => [`node_modules/${k}`, v])) } });
// Text a GitHub comment would render as a mention: "@x" after a non-word character, outside code spans.
const bareMentions = (md) => md.split(/(`[^`\n]*`)/).filter((_, i) => i % 2 === 0).join('').match(/(^|[^\w`@/])@[A-Za-z0-9][\w.-]*/gm) || [];

test('lockfile REPORT and dataset markdown carry no bare @mentions', async () => {
    const before = lock({ '@solana/web3.js': pub('@solana/web3.js', '1.95.6'), '@types/old': pub('@types/old', '1.0.0'), '@babel/core': pub('@babel/core', '7.0.0') });
    const after = lock({ '@solana/web3.js': pub('@solana/web3.js', '1.95.7'), '@octo/new': pub('@octo/new', '2.0.0'), '@babel/core': pub('@babel/core', '7.0.1') });
    const io = memoryIo({
        analyze: async (s) => (s.name === '@babel/core'
            ? { ecosystem: s.ecosystem, name: s.name, error: 'tarball for @babel/core failed' }
            : { ecosystem: s.ecosystem, name: s.name, fromVersion: s.from, toVersion: s.to, verdict: s.name.startsWith('@solana') ? 'review' : 'clean', findings: s.name.startsWith('@solana') ? [{ category: 'security', severity: 'high', title: 'New dependency @evil/drain first published 2 days ago' }] : [], counts: {}, coverage: { complete: true } }),
    });
    await runInput({ lockfileBefore: before, lockfileAfter: after }, io);
    assert.match(io.kv.REPORT, /`@solana\/web3\.js`/);
    assert.match(io.kv.REPORT, /`@types\/old`/, 'removed-packages list is quoted too');
    assert.deepEqual(bareMentions(io.kv.REPORT), []);
    assert.ok(io.items.length > 0);
    for (const item of io.items) assert.deepEqual(bareMentions(item.markdown || ''), [], item.name);
});

test('quoteMentions leaves code spans and e-mail addresses alone and is idempotent', () => {
    const md = 'From `@a/b` by dev@example.com; see @c/d and (@e).';
    const once = quoteMentions(md);
    assert.equal(once, 'From `@a/b` by dev@example.com; see `@c/d` and (`@e`).');
    assert.equal(quoteMentions(once), once);
});
