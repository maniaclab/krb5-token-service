"""Kerberos credential cache (ccache) parsing.

Uses pykrb5 (bindings over MIT's libkrb5) to extract the fields the mint
response reports, rather than shelling out to a second binary. ``klist``'s
timestamp formatting is locale-dependent — ``krb5_timestamp_to_sfstring``
tries the "%c" format first — so it is not a stable machine-readable
contract; ``python-gssapi`` was evaluated as an alternative but exposes no
``renew_till``, which this service's response needs (the shipped krb5.conf
sets ``renew_lifetime = 7d`` precisely so a consumer can renew for a week
without re-supplying the password). This mirrors voms-token-service's
minting.py:_parse_proxy_pem: parse the artifact this service just minted,
in-process, with a library already in the dependency graph.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import krb5

if TYPE_CHECKING:
    from pathlib import Path

# Server principal realm MIT krb5 uses for non-ticket "config entries" it
# stores alongside real credentials in a ccache (e.g. fast_avail, pa_type) —
# see doc/formats/ccache_file_format.rst. These carry an all-zero endtime and
# must never be mistaken for the TGT.
_CONFIG_ENTRY_REALM = b"X-CACHECONF:"


class CcacheParseError(Exception):
    """Raised when the just-minted ccache carries no usable TGT.

    Should not happen for a ccache kinit itself just wrote successfully; if
    it does, the ccache is unusable and this is treated as an infra failure
    like any other minting error.
    """


@dataclass(frozen=True)
class CcacheInfo:
    principal: str
    realm: str
    expires_at: datetime
    renew_until: datetime | None


def read_ccache(path: Path) -> CcacheInfo:
    """Parse *path* (a FILE-type ccache kinit just wrote) for the mint response.

    The cache's default principal identifies the realm; the ticket-granting
    ticket (server principal ``krbtgt/<realm>@<realm>``) carries the times
    the KDC actually granted — which is what's reported, not the request's
    lifetime/renewable_lifetime (the KDC may cap either below what was asked
    for).
    """
    ctx = krb5.init_context()
    cc = krb5.cc_resolve(ctx, f"FILE:{path}".encode())
    principal = krb5.cc_get_principal(ctx, cc)
    realm = principal.realm.decode()
    tgt_server = f"krbtgt/{realm}@{realm}"

    for cred in cc:
        if cred.server.realm == _CONFIG_ENTRY_REALM:
            continue
        if str(cred.server) == tgt_server:
            times = cred.times
            return CcacheInfo(
                principal=str(principal),
                realm=realm,
                expires_at=datetime.fromtimestamp(times.endtime, tz=UTC),
                renew_until=(
                    datetime.fromtimestamp(times.renew_till, tz=UTC)
                    if times.renew_till
                    else None
                ),
            )

    raise CcacheParseError(f"no {tgt_server} credential found in minted ccache")
