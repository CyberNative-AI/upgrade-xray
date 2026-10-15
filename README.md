# Upgrade X-Ray

**See what a dependency update really changes before you merge it — computed from the published npm and PyPI files, not from the changelog.**

For each update, Upgrade X-Ray downloads the old and new published artifacts (npm tarball, PyPI wheel and sdist), verifies them against the registry's checksums and compares them statically. Nothing is installed or executed. It reports:

- **New install-time code** — new or changed `preinstall` / `install` / `postinstall` scripts, implicit `node-gyp` builds, `setup.py` command hooks, in-tree build backends, and `.pth` / `sitecustomize` files that run at every Python start-up.
- **New network, shell or eval calls** — new uses of `child_process`, `subprocess`, `fetch`, `http(s)`, `socket`, `requests`, `eval`, `exec`, `new Function`, `vm`, and code launched with inline or base64-encoded payloads.
- **High-risk indicators** — obfuscation (including code hidden after long runs of spaces and payloads hidden in invisible Unicode characters), reads of credential files (`.npmrc`, `.ssh`, cloud and wallet keys), exfiltration-style endpoints, token theft and self-publishing, persistence, overrides of global `fetch` / `XMLHttpRequest` / wallet functions, and new executables.
- **Removed functions** — exports removed from each entry point or module (JS, TypeScript declarations, Python public names), removed import paths and commands, a switch to ES modules, and raised engine / Python requirements.
- **New dependencies** — with their age and owner: a dependency first published days before the release by *different* maintainers is flagged high; one that does not exist on the registry, or comes from git or a URL, is flagged high.

Each package gets a verdict: **🔴 review before merge**, **🟡 worth a look**, or **🟢 nothing new found**.

## Two ways to run it

**Package mode** — one or more updates, charged per package:

```json
{ "packages": ["npm:axios@1.7.9..1.8.0", "pypi:requests@2.31.0..2.32.0", "pypi:urllib3==2.5.0", "esbuild"] }
```

`name@from..to` compares two versions; `name@to` or `pypi:name==to` compares a version with the release before it; a bare name compares the previous release with the latest.

**Lockfile mode** — the old and new lockfile of a pull request, one report for every changed package:

```json
{ "lockfileBefore": "<old package-lock.json>", "lockfileAfter": "<new package-lock.json>" }
```

Supported: `package-lock.json` / `npm-shrinkwrap.json` (v1–v3), `pnpm-lock.yaml` (v5–v9), `uv.lock`, `poetry.lock`. You can also pass raw URLs (`lockfileBeforeUrl`, `lockfileAfterUrl`). Packages new to the tree are checked for install scripts and high-risk indicators. Packages that come from private registries, git, URLs or local paths are listed but **not looked up** — their names are not sent to any registry.

## Output

- **Dataset** — one item per package: verdict, findings with file and line, new and removed dependencies, API changes, and a ready-to-post markdown section.
- **Key-value store** — `REPORT` (the full markdown verdict, e.g. for a pull-request comment) and `OUTPUT` (summary JSON).

AI agents can call it through the Apify MCP server; the markdown is designed to be pasted into a pull-request review as is.

## Pricing

Pay per event, no subscription:

| Event | Price |
|---|---|
| Package diff (package mode) | $0.02 per package analysed |
| Lockfile report (lockfile mode) | $0.25 per report, up to 150 changed packages (configurable to 300) |

Packages that cannot be analysed (not found, too large) are not charged. A run never goes over the maximum charge you set.

## Measured accuracy

Measured on 2026-10-15 with the detectors frozen in advance. Detectors were tuned on a *dev* split only; the numbers below are from the *holdout* split, which was run once. The split is a fixed hash of the package name, so every version of a package falls on the same side.

**Compromised versions.** Labelled compromised versions of legitimate packages from the [Datadog malicious software packages dataset](https://github.com/DataDog/malicious-software-packages-dataset) (`compromised_lib`, Apache-2.0), each compared with the closest earlier clean version from the registry:

| Holdout set | Flagged "review before merge" |
|---|---|
| All comparable updates | **988 / 998 (99.0%, 95% CI 98.2–99.5%)** |
| npm | 982 / 988 |
| PyPI | 6 / 10 |
| First compromised version of each package only | 698 / 703 |
| Compromised first releases (no earlier version, scanned as new packages) | 43 / 47 |

Excluded and listed separately: 12 samples that are a git checkout rather than the published file, 2 samples with no code, and 28 whose earlier clean version is no longer on the registry.

**Read these numbers with care.** Most samples come from a few large worm campaigns (September and November 2025, May–June 2026) that add install scripts and obvious credential theft — the easy case for this kind of tool. The misses are the targeted attacks that hid key theft inside normal code paths of the package: `xrpl` 4.2.1–4.2.4 and 2.14.2, `@solana/web3.js` 1.95.7, `litellm` 1.82.7, `lightning` 2.6.2–2.6.3 and `guardrails-ai` 0.10.1 (`xrpl` 2.14.2, `lightning` and `guardrails-ai` got "worth a look", the rest "nothing new"). PyPI coverage is small. Treat the tool as a reader's guide to what changed, not a malware scanner.

**Benign major bumps.** The latest major-version bump of the most-downloaded packages on npm and PyPI (ranking from ecosyste.ms, picked in rank order, not by hand):

| Holdout set | "Review before merge" (false alarm) | "Worth a look" |
|---|---|---|
| 50 npm + 50 PyPI major bumps | **0 / 100 (95% CI 0–3.7%)** | 12 / 100 |

The full per-sample results, the selection script and the harness are in [`fixtures/`](fixtures/). Rates will be re-measured on compromised versions published after this date.

## Limits

- Static analysis of JavaScript, TypeScript and Python. Native binaries are reported as new files, not analysed. Lines and files above the size limits are skipped and noted.
- A dependency's age and owner are read from the registry at run time.
- npm packages are compared as published (one tarball). For PyPI, the best wheel and the sdist are compared separately and merged; very large distributions (over 60 MB) are not analysed.
- A finding is a change worth reading, not proof of malice; an empty report does not prove a package is safe.

## Privacy

Package mode sends only package names and versions to the public registries. In lockfile mode, the lockfile text is read inside the run and stored nowhere except the run's own Apify storage, under your account's retention settings. Private, git and URL dependencies are never looked up.

## About

Built and maintained by **CyberNative AI LLC**, an AI-run company: the tool, the detectors and this README were written by AI agents. Issues and false-alarm reports are welcome on the repository.
