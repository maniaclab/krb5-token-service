# krb5-token-service

Kerberos ticket minting for the UChicago ATLAS Analysis Facility MCP
platform. A sibling of [voms-token-service](https://github.com/maniaclab/voms-token-service),
following the same scaffolding and the same AF Broker Identity Token
protocol, with `voms-proxy-init` swapped for `kinit` against CERN's realm.

## Why this service exists

Minting a Kerberos ticket for a CERN account requires a CERN username and
the password that unlocks it. Both are trust-domain-defining: the password
must never reach the [af-mcp-broker](https://github.com/maniaclab/af-mcp-platform)
(a different trust domain holding many other credentials).

This service receives a user's CERN username and password over HTTPS, runs
`kinit` against CERN's realm, and returns the resulting credential cache
(ccache) in the response body. Unlike voms-token-service, **no on-disk user
credential is required to mint against** — the password on the wire is the
entire credential — so this service mounts no shared storage at all, needs
no elevated capability, and runs as a single unprivileged uid for its whole
lifetime. The ccache is staged in a private 0700 directory on the pod's own
tmpfs, read back into memory, and discarded; the password lives only in
memory and is zeroed immediately after use.

```
 LLM client                af-mcp-platform                 krb5-token-service              CERN KDC
     |                          |                                |                              |
     |  MCP tool call           |                                |                              |
     +------------------------->|                                |                              |
     |                 [broker authenticates &                    |                              |
     |                  authorizes the user]                      |                              |
     |                          |  POST /v1/mint                 |                              |
     |                          |  Bearer: AF Broker              |                              |
     |                          |  Identity Token (RS256)         |                              |
     |                          |  {username, password,           |                              |
     |                          |   lifetime, renewable_lifetime} |                              |
     |                          +------------------------------->|                              |
     |                          |                        krb5-token-service                     |
     |                          |                                |                              |
     |                          |                    verify JWT (broker JWKS)                    |
     |                          |                    check per-username rate limiter             |
     |                          |                                |                              |
     |                          |                    kinit -c FILE:<ccache>                      |
     |                          |                      -l <lifetime>                             |
     |                          |                      -r <renewable_lifetime>                   |
     |                          |                      <username>@CERN.CH                        |
     |                          |                                +----------------------------->|
     |                          |                                |<-----------------------------+|
     |                          |                    [password zeroed from                       |
     |                          |                     memory immediately;                         |
     |                          |                     ccache read back, tmpdir removed]           |
     |                          |<-------------------------------+                              |
     |                          |  {ccache_b64, principal, realm, |                              |
     |                          |   expires_at, renew_until}      |                              |
```

## The credential it verifies

This is a consumer of the **AF Broker Identity Token** internal protocol
([maniaclab/af-mcp-platform#162](https://github.com/maniaclab/af-mcp-platform/issues/162)),
the same protocol [voms-token-service](https://github.com/maniaclab/voms-token-service)
and [condor-token-service](https://github.com/maniaclab/condor-token-service)
consume: a short-lived RS256 JWT minted by the broker with claims
`iss`/`sub`/`aud`/`exp`/`iat`/`jti`. These are **identity assertions, not
capability claims** — the broker has already authorized the call before
minting the token, and this service derives no authorization from token
claims. A missing or invalid token is refused (401).

The `username`/`password` to mint a ticket for come from the **request
body**, not the token — mirroring voms-token-service's own `unixname` field.

Verification fetches the broker's JWKS from `BROKER_JWKS_URL` (TTL-cached,
single-flight refresh, stale-served on fetch failure), then enforces
signature, issuer, audience, and expiry. Every request produces exactly one
JSON audit line — subject, username, confirmed principal, broker-token
`jti`, outcome (`issued|denied|error`), request id — and neither the
password nor the minted ccache is ever logged (`logging.py`'s
`SensitiveValueRedactProcessor` is the defense-in-depth backstop if a future
code path gets this wrong).

## API

| Endpoint | Auth | Behavior |
| --- | --- | --- |
| `POST /v1/mint` | `Authorization: Bearer <AF Broker Identity Token>` | Body `{"username": str, "password": str, "lifetime": str, "renewable_lifetime": str}` **or** `{"username": str, "keytab_b64": str, "lifetime": str, "renewable_lifetime": str}` — exactly one of `password`/`keytab_b64` is required (422 otherwise); `lifetime`/`renewable_lifetime` optional, krb5 "time duration" strings — see below. Mints a Kerberos ticket via `kinit` (password on stdin, or `-kt` against the decoded keytab) for `<username>@CERN.CH`. Returns `{"ccache_b64", "principal", "realm", "expires_at", "renew_until"}` (`renew_until` is `null` when the ticket isn't renewable). 400 `{"detail": "bad password"}` / `{"detail": "bad keytab"}` / `{"detail": "unknown principal"}`; 403 when the CERN account itself is revoked or its password has expired (fixed, user-actionable detail — never kinit's raw stderr); 422 on an invalid `username`/`lifetime`/`keytab_b64`; 429 after too many recent failed passwords for that username (the keytab path never triggers this — see "Rate limiting" below); 401 invalid/missing token; 502 on any other minting failure (generic detail — kinit's stderr is logged server-side only, never returned). |
| `POST /v1/renew` | `Authorization: Bearer <AF Broker Identity Token>` | Body `{"ccache_b64": str}` — a ccache this service minted earlier. Runs `kinit -R` on it; no credential is involved at all, so this never touches the rate limiter. Same response shape as `/v1/mint`. 422 `{"detail": "invalid ccache_b64"}` / `{"detail": "invalid ccache"}` when the input isn't valid base64 or isn't a real ccache (checked with `ccache.py` **before** `kinit` is ever invoked); 400 once the ticket is past its own `renew_until` — mint a fresh one via `/v1/mint` instead; 401/502 as above. |
| `POST /v1/keytab` | `Authorization: Bearer <AF Broker Identity Token>` | Body `{"username": str, "password": str}`. Bootstraps a fresh keytab via CERN's own `cern-get-keytab` (patched — see below) and returns `{"keytab_b64", "principal"}`. **Never persists the keytab** — the caller (the broker) is responsible for storing it, e.g. in its own vault, for future `/v1/mint` keytab-mode calls. Shares the failed-auth rate limiter with `/v1/mint`'s password path (see "Rate limiting" below) — a wrong password here is a real check against the same CERN account. 400 `{"detail": "bad password"}`; 422 on an invalid `username`; 429 after too many recent failures; 401/502 as above. |
| `GET /healthz` | none | Always 200. |
| `GET /readyz` | none | 200 only when `kinit` is executable, `KRB5_CONFIG` is readable, and the broker JWKS is fetchable; 503 otherwise. Deliberately does **not** check CERN KDC reachability (a CERN-side outage must not flap this pod's readiness) and does **not** check `cern-get-keytab`/`msktutil` (a bootstrap convenience with its own, slower CERN-side dependency — LDAP, not just the KDC — that must not flap readiness either). |

Configuration is env-driven (`src/krb5_token_service/config.py`):
`BROKER_JWKS_URL`, `BROKER_ISSUER`, `EXPECTED_AUDIENCE`, `KINIT_BIN`,
`KRB5_CONFIG`, `DEFAULT_REALM`, `DEFAULT_LIFETIME`,
`DEFAULT_RENEWABLE_LIFETIME`, `CCACHE_TMP_ROOT`, `KINIT_TIMEOUT_SECONDS`,
`CERN_GET_KEYTAB_BIN`, `CERN_GET_KEYTAB_TIMEOUT_SECONDS`,
`FAILED_AUTH_MAX_ATTEMPTS`, `FAILED_AUTH_WINDOW_SECONDS`,
`FAILED_AUTH_LOCKOUT_SECONDS`, `JWKS_CACHE_TTL_SECONDS`, `LOG_LEVEL`.

## The exact kinit invocation

```
kinit -c FILE:<private-tmpdir>/ccache -l <lifetime> -r <renewable_lifetime> <username>@CERN.CH
```

The password is written to stdin (never argv, never logged) as a
`bytearray`, and that buffer — plus the stdin copy built at the subprocess
I/O boundary — is zeroed (`_zero_bytearray` in `minting.py`, the same
discipline as voms-token-service's `minting.py`) immediately after the
subprocess returns, on every path: success, bad password, or timeout. MIT
krb5's own prompter explicitly supports a non-tty stdin
(`src/lib/krb5/os/prompter.c`'s `setup_tty` short-circuits when
`!isatty(fd)`), so this is the direct analogue of voms-proxy-init's
`--pwstdin`. The private tmpdir holding the ccache is removed once its
contents have been read back into memory (`tempfile.TemporaryDirectory`).
The subprocess call itself is a synchronous `subprocess.run(timeout=...)`
offloaded to a thread via `run_in_executor` — mirroring voms-token-service's
own pattern — so the timeout is enforced by the stdlib's own process kill on
expiry.

**Principal, expiry, and renewal are read from the ccache itself, not
`klist`.** `klist`'s timestamp formatting is locale-dependent
(`krb5_timestamp_to_sfstring` tries the C locale's `%c` format first), so it
is not a stable machine-readable contract. `python-gssapi` was evaluated as
an alternative and rejected: it exposes ticket `lifetime` but no
`renew_till`, and this service's response needs the KDC-confirmed renewal
deadline (the shipped `krb5.conf` sets `renew_lifetime = 7d` precisely so a
consumer can `kinit -R` for a week without re-supplying the password).
Instead, `src/krb5_token_service/ccache.py` parses the FILE-ccache v4 bytes
kinit just wrote directly with `pykrb5` (bindings over the same libkrb5),
skipping the non-ticket `X-CACHECONF:` config entries every real MIT ccache
carries and reading the `krbtgt/<realm>@<realm>` credential's confirmed
`endtime`/`renew_till` — the same "parse what we just minted, in-process,
with a library already in the dependency graph" design point as
voms-token-service's `_parse_proxy_pem`.

**Real kinit/KDC error strings, not guesses.** The `kinit` stderr markers
`minting.py` matches against (`"Password incorrect"`, `"not found in
Kerberos database"`, `"credentials have been revoked"`, `"Password has
expired"`) were verified against MIT krb5's own source
(`clients/kinit/kinit.c`'s error-formatting branch and
`lib/krb5/error_tables/krb5_err.et`), not assumed — and, while validating
this service's Containerfile locally, `kinit` against a nonexistent
principal reached CERN's real KDC and returned `Client
'nonexistentuser@CERN.CH' not found in Kerberos database`, confirming the
marker against a live response.

## Renewal and keytab bootstrap

Two more ways to get (or keep) a ticket besides a bare password mint:

**`kinit -R` renewal (`/v1/renew`)** costs nothing to call — no password,
no keytab, just the ccache this service minted earlier — but is capped at
that ticket's own `renew_until` (the shipped `krb5.conf`'s `renew_lifetime
= 7d`): past that, `kinit -R` fails with `"Ticket expired while renewing
credentials"` and the caller must mint a fresh ticket instead.

**Keytab-based minting (`/v1/mint` with `keytab_b64`)** trades a one-time
password for a long-lived credential: a keytab lets `kinit -kt` mint fresh
tickets indefinitely (each with its own fresh 7-day renew window) without
ever re-supplying the password, and — unlike storing the plaintext password
itself long-term — a leaked keytab is scoped to Kerberos and rotatable by
kvno. This service never generates a keytab itself during a mint; it only
consumes one the caller already has.

**`POST /v1/keytab`** is how the caller gets that keytab in the first
place, via CERN's own `cern-get-keytab` (`msktutil`-backed, since CERN's
realm is an Active Directory domain). The upstream script is vendored
as-is at `etc/cern-get-keytab`, with fixes applied as
`etc/cern-get-keytab.patch` at image build time (`git apply`/`patch`,
never hand-edited in place) — re-vendoring a newer upstream release just
means dropping in the new file and re-applying the patch:

- **A real shell-injection bug.** `call_msktutil` builds `--old-account-password '<password>'` (naive single-quote wrapping, no escaping) and runs the whole command line under `subprocess.Popen(..., shell=True)`. A password containing a single quote breaks out of the quoting into arbitrary shell execution inside this pod — this is CERN's own script, not something fixable upstream from here, so the patch wraps both occurrences in `shlex.quote()` instead.
- **A stdin-based password input the script didn't have.** Non-interactively, `cern-get-keytab -u` only accepts `-p <password>` (visible in this pod's own `/proc/<pid>/cmdline` for the subprocess's lifetime) — `getpass.getpass()`'s interactive fallback explicitly reads `/dev/tty`, bypassing a redirected stdin entirely by design. The patch adds an `isatty()`-gated stdin read before that fallback, mirroring MIT `kinit`'s own `prompter.c` (`if (!isatty(fd))`) — see `mint_keytab`'s docstring in `minting.py`.
- **Discarded failure diagnostics.** By default `cern-get-keytab` throws away `msktutil`'s stderr on failure entirely unless `--verbose` is passed, and even then only echoes the (already-redacted) command line, never the actual error. The patch surfaces it unconditionally so this service has something to classify a failure by at all.

That last fix mattered in practice: verified against CERN's real Active
Directory backend (a deliberately wrong password, never a real account),
`msktutil`'s internal `--use-service-account` credential machinery is more
involved than a single `krb5_get_init_creds_password` call — it tries
several strategies (`msktkrb5.cpp`'s `try_machine_password` /
`try_machine_supplied_password` / `try_user_creds`), and each one's own
`"Preauthentication failed"`-style error lands on `cern-get-keytab`'s
**stdout** (verbose progress output already printed unconditionally), not
stderr. Only `msktutil`'s own top-level summary —
`"Could not find any credentials to authenticate with..."` — reaches
stderr, and only because of the patch's fourth fix above; without it, every
`/v1/keytab` failure would have surfaced as a generic 502 rather than a 400.
That summary also doesn't distinguish a wrong password from a genuinely
unknown account the way `kinit`'s own errors do, so — unlike `/v1/mint` —
there is no separate `unknown principal` outcome for `/v1/keytab`; both
count as `bad password` and both count against the rate limiter.

## Rate limiting — unlike voms-token-service

**voms-token-service deliberately has no rate limiter**: a wrong Globus
passphrase only fails a local openssl decrypt with no consequence outside
that pod, and the broker's own `CredentialCache` already throttles
credential-unlock attempts per uid before ever calling either service.

**This service adds one anyway**, because the consequence of a wrong
password is sharper here: `kinit` sends a real AS-REQ to CERN's KDC, and
repeated failures count against **CERN's own account-lockout policy** — a
bug or a compromised broker retrying too aggressively could lock a real
person out of their CERN account, not just fail a local decrypt. The broker
throttle is still the primary defense; this service's per-username
sliding-window limiter (`src/krb5_token_service/ratelimit.py`,
`FAILED_AUTH_MAX_ATTEMPTS` failures within `FAILED_AUTH_WINDOW_SECONDS`
locks that username out for `FAILED_AUTH_LOCKOUT_SECONDS`) is a backstop:
`kinit` is never invoked on a blocked attempt, so the KDC never sees it. A
failure is counted **only** on a confirmed bad password — never on an
unknown principal or an infra failure (KDC unreachable, timeout), neither of
which is evidence of a guessing attempt.

The limiter is keyed by username and shared across every path that actually
checks a password against CERN: `/v1/mint`'s password mode and `/v1/keytab`
both count against it (see "Renewal and keytab bootstrap" above for why
`/v1/keytab` can't cleanly separate a bad password from an unknown account
the way `/v1/mint` does — both count there). `/v1/mint`'s keytab mode and
`/v1/renew` never touch it at all: neither involves a password.

The limiter is in-process, per-replica state — see "Deployment" below for
why the chart defaults to a single replica.

## Deployment

The Helm chart at `charts/krb5-token-service/` encodes the (much simpler)
privilege model this service needs:

- **No elevated capability, no shared storage.** Unlike voms-token-service
  (`runAsUser: 0` + `CAP_DAC_READ_SEARCH` + `CAP_SETUID`/`CAP_SETGID`, to
  read arbitrary users' NFS-mounted certificate files and impersonate them),
  `kinit` needs no on-disk user credential at all — the password on the
  wire is the entire credential. The chart runs the pod as a single fixed
  unprivileged uid (`podSecurityContext.runAsUser: 1000`) with `capabilities:
  {drop: [ALL]}` and no `add:` list, a read-only root filesystem (the ccache
  lives only in a `Memory`-backed `emptyDir` at `/tmp`), no privilege
  escalation, and `RuntimeDefault` seccomp. There is no PVC, no init
  container, and no sidecar.
- **Single replica by default.** The failed-authentication limiter above is
  in-process, per-replica state: running N replicas multiplies the effective
  attempt budget against the same CERN account by N before this service's
  own limiter engages. `values.yaml` documents the arithmetic; lower
  `config.failedAuthMaxAttempts` if you must run more than one replica.
- **`krb5.conf` delivery.** The file this repo ships (`etc/krb5.conf`,
  realm `CERN.CH`, `kdc = cerndc.cern.ch`) is baked into the image at
  `/app/etc/krb5.conf` and used as-is by default — matching
  voms-token-service's "no ConfigMap, all configuration is env-from-values"
  stance for its own trust material. Set `krb5Config.override: true` to
  instead render `krb5Config.contents` into a ConfigMap mounted over that
  same path via `subPath`, so a CERN KDC hostname change needs no image
  rebuild. Depending on your resolver/network setup, you may need to add
  `dns_canonicalize_hostname = false` under `[libdefaults]` in that
  overridden config to stop the DNS lookup from canonicalizing the KDC
  hostname — confirmed necessary at UChicago's AF.
- **NetworkPolicy** — ingress only from the broker pods; egress limited to
  DNS, the broker JWKS origin, and the CERN KDC(s) `kinit` contacts, opened
  on **both UDP and TCP port 88** (all `ipBlock` rules, since these servers
  are external to the cluster and DNS names can't appear directly in a
  `NetworkPolicy`; restrict `networkPolicy.kdc.cidr` to CERN's real KDC
  IPs/CIDRs in production). Both protocols matter: MIT krb5 tries UDP first
  and falls back to TCP when a reply doesn't fit in one datagram — allowing
  only one silently breaks minting.

```bash
helm lint charts/krb5-token-service
helm template krb5-token-service charts/krb5-token-service
helm template krb5-token-service charts/krb5-token-service --set krb5Config.override=true
```

The `Containerfile` builds the runtime image: debian-slim plus the
pixi-built Python environment. `kinit`/`klist` come from conda-forge's
`krb5` package (`pixi.toml`'s `service` feature) — like voms-token-service's
`voms` package, the Kerberos clients ride in the same pixi environment as
the Python service. `msktutil` (`cern-get-keytab`'s own Active-Directory
dependency) isn't on conda-forge, so it comes from `apt` in the final stage
instead, alongside `ca-certificates` (for verifying the broker's JWKS TLS
endpoint) — the one package-manager step beyond the pixi env. The builder
stage applies `etc/cern-get-keytab.patch` and only the already-patched
script is copied into the final image; `/usr/bin/kinit`/`/usr/bin/klist` are
symlinked to the pixi env's binaries there too, since `cern-get-keytab`
hardcodes those absolute paths for its own (best-effort, non-load-bearing)
KVNO reporting. Unlike voms-token-service's image (which deliberately
carries no `USER` directive — its privilege model is entirely in the
chart), this image sets `USER 1000:1000` directly, since nothing it does
ever needs root.

## Local development

Everything runs through [pixi](https://pixi.sh); dependencies live in
`pixi.toml` (this package's `pyproject.toml` intentionally declares no
dependencies).

```bash
pixi run serve        # dev server with reload → http://localhost:8080/docs
pixi run test         # pytest tests/ -v
pixi run lint         # ruff check + format --check
pixi run fmt          # ruff format + autofix
pixi run typecheck    # mypy --strict src
pixi run -e dev lint-all   # everything the CI lint job runs (ruff + mypy + pre-commit)
```

The default test suite never touches the network, a real CERN KDC, or a
real filesystem beyond pytest's own `tmp_path`: the JWKS is served by an
in-process stub around a real generated RSA keypair
(`tests/conftest.py::stub_jwks_fetch`), and `kinit`/`cern-get-keytab` are
fake executables on `PATH` (or, for `cern-get-keytab`, a plain Python script
pointed at directly, matching how `mint_keytab` really invokes it) covering
every mode — password, `-kt`, `-R` — and writing a real, `pykrb5`-parseable
FILE-ccache v4 byte string as their output (`tests/ccache_fixtures.py` —
verified against MIT krb5's own `doc/formats/ccache_file_format.rst` and
`src/lib/krb5/ccache/ccmarshal.c`, so `ccache.py`'s parsing exercises the
real wire format, not a hand-rolled fake). `tests/test_e2e.py` is skipped
unless `KRB5_E2E=1`, and requires a real deployment, a real broker-minted
token, and a real CERN password for a real CERN account — it is never
faked:

```bash
KRB5_E2E=1 \
  KRB5_TOKEN_SERVICE_URL=https://krb5-token.af.uchicago.edu \
  AF_BROKER_IDENTITY_TOKEN=<freshly-minted broker token> \
  KRB5_E2E_USERNAME=<real CERN username> \
  KRB5_E2E_PASSWORD=<real CERN password> \
  pixi run test
```
