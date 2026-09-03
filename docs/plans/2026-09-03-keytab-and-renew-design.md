# Keytab minting, ticket renewal, and keytab bootstrap

## Context

`/v1/mint` only ever consumed a password. Two related but distinct needs
came up:

1. A way to extend a ticket's life without asking the user for their
   password again (`kinit -R`).
2. A way to mint tickets from a long-lived credential instead of a
   password — CERN's own `cern-get-keytab` (`msktutil`-backed, since CERN's
   realm is an Active Directory domain) issues keytabs for exactly this.

The explicit non-goal: this service must never store a minted ticket, a
password, or a keytab itself. Whatever upstream vault holds a linked
credential (password or keytab) hands it to this service per-request; this
service mints and forgets.

## Decision: three capabilities, not one

- **`POST /v1/renew`** — `kinit -R` on a ccache this service minted earlier.
  No credential at all; bypasses the rate limiter entirely. Capped at the
  ticket's own `renew_until` (7d, per the shipped `krb5.conf`).
- **`POST /v1/mint` extended** — body takes `password` *or* `keytab_b64`
  (exactly one, pydantic `model_validator`). Keytab mode runs `kinit -k -t
  <path>`, no stdin.
- **`POST /v1/keytab`** — bootstraps a *new* keytab from a password via
  CERN's `cern-get-keytab`. Shares the rate limiter with `/v1/mint`'s
  password path (see below for why). Returns the keytab bytes; never
  persists them.

## `cern-get-keytab`: vendor as-is, patch separately

Per explicit instruction: `etc/cern-get-keytab` stays byte-for-byte what
CERN ships. Every fix is `etc/cern-get-keytab.patch`, applied at image
build time (builder stage; only the patched script ships in the final
image). Re-vendoring a newer upstream release is: drop in the new file,
re-apply the patch, resolve conflicts if CERN moved the relevant lines.

Three real problems found by reading the vendored script, one only found by
running it for real:

1. **Shell injection.** `call_msktutil` builds `--old-account-password
   '<password>'` — naive single-quote wrapping, zero escaping — then runs
   the whole line under `subprocess.Popen(shell=True)`. A password
   containing `'` breaks out into arbitrary shell execution inside this
   pod. Fixed with `shlex.quote()` (both occurrences).
2. **No non-interactive stdin input.** Only `-p <password>` (argv,
   `/proc/<pid>/cmdline`-visible) or an interactive `getpass()` that
   explicitly reads `/dev/tty`, bypassing a redirected stdin by design.
   Added an `isatty()`-gated stdin read ahead of the `getpass()` fallback —
   deliberately mirrors MIT `kinit`'s own `prompter.c` logic
   (`if (!isatty(fd))`), verified against that source earlier in this same
   effort.
3. **Discarded failure diagnostics.** `do_execute()`'s failure branch only
   echoes the (redacted) command line under `--verbose`, and never prints
   `msktutil`'s actual stderr at all otherwise. Added an unconditional
   `print(err, file=sys.stderr)` in that branch.

Fix 3 turned out to be load-bearing in a way source-reading alone couldn't
show. **Verified against CERN's real AD backend** (a deliberately wrong
password against a nonexistent test account — never a real one):
`msktutil`'s `--use-service-account` path tries several internal
strategies (`try_machine_password` / `try_machine_supplied_password` /
`try_user_creds` in `msktkrb5.cpp`), and each one's own
`"Preauthentication failed"`-style error lands on **stdout** (verbose
progress output, already unconditionally printed) — not stderr. Only
`msktutil`'s own top-level summary, `"Could not find any credentials to
authenticate with..."`, reaches stderr, and only because of fix 3. Without
it, `minting._classify_cern_get_keytab_stderr` would never see *any*
distinguishing text, and every `/v1/keytab` failure — including an
ordinary wrong password — would have surfaced as a generic 502 instead of
400.

That same summary doesn't distinguish a wrong password from a genuinely
unknown account. Unlike `/v1/mint` (which gets a clean `"not found in
Kerberos database"` from `kinit` itself), `/v1/keytab` has no
`UnknownPrincipalError` path — both outcomes classify as `BadPasswordError`
and both count against the rate limiter. Disclosed trade-off, not an
oversight: `msktutil` genuinely doesn't expose the distinction here.

## Rate limiter scope

`/v1/keytab`'s `--old-account-password` check is a real credential
verification against the same CERN account `/v1/mint`'s password path
checks — both risk CERN's own account-lockout policy — so both share one
`RateLimiter` instance, keyed by username. `/v1/mint`'s keytab mode and
`/v1/renew` never touch it: neither involves a password.

## `msktutil` packaging

Not on conda-forge (checked both the `anaconda.org` search API and
`conda-forge/msktutil-feedstock` directly — neither exists). It *is* a real
Debian bookworm package (`1.2-2`, matching the base image exactly), so it
comes from `apt-get` in the Containerfile's final stage, alongside
`ca-certificates`.

`cern-get-keytab` also hardcodes `/usr/bin/kinit` and `/usr/bin/klist`
(absolute paths, for its own best-effort KVNO reporting) — this image's
real binaries live under the pixi env instead, so the Containerfile
symlinks them into place. `cern-get-keytab` is always invoked as
`sys.executable <script> ...` (never via its own `#!/usr/bin/python3`
shebang), so no system `python3` is needed.

## What shipped

- `src/krb5_token_service/minting.py` — `renew_ticket`, `mint_keytab`,
  `mint_ticket` extended for keytab input; per-mode stderr classifiers
  (password / keytab / renew / cern-get-keytab), each with markers verified
  against real MIT krb5 source or, for `cern-get-keytab`, a real run.
- `src/krb5_token_service/ccache.py` — `read_ccache` now wraps
  `krb5.Krb5Error` (genuinely malformed input, not just "no TGT") into
  `CcacheParseError` too — found by the first `renew_ticket` test written
  against a garbage ccache; `pykrb5` raised its own exception type instead
  of ours.
- `src/krb5_token_service/app.py` — `POST /v1/renew`, `POST /v1/keytab`,
  `POST /v1/mint`'s `model_validator` for exactly-one-credential.
- `etc/cern-get-keytab` (vendored) + `etc/cern-get-keytab.patch`.
- `Containerfile` — patch application, `msktutil` + symlinks.
- `charts/krb5-token-service/` — two new `config.*` values
  (`cernGetKeytabBin`, `cernGetKeytabTimeoutSeconds`).
- Tests: `tests/test_minting.py` extended; new `tests/test_renew_endpoint.py`,
  `tests/test_keytab_endpoint.py`; `tests/conftest.py` fake-binary fixtures
  for every new mode.

## Verification

`pixi run -e dev lint-all` (ruff + mypy --strict + pre-commit incl.
zizmor), `pixi run -e dev test` (147 passed, 1 skipped — `test_e2e.py`),
`helm lint`/`helm template`, and a real `docker build` + container run:
confirmed `msktutil`/symlinks/patch/imports all resolve inside the actual
image, and confirmed the stdin-password patch works at runtime (not just
present in source) against CERN's real AD backend — including the
stdout/stderr split finding above, which only showed up this way.
