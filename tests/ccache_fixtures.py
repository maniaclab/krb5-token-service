"""Real (not hand-rolled-fake) MIT FILE-ccache v4 byte builder, for tests.

Mirrors voms-token-service's tests/conftest.py:fake_proxy_pem — tests
produce real bytes in the exact wire format the parser (ccache.py) consumes,
verified against MIT krb5's doc/formats/ccache_file_format.rst,
src/lib/krb5/ccache/ccmarshal.c (principal/credential layout), and
src/lib/krb5/ccache/cc_file.c (the version bytes and v4 header-fields block:
``read_header`` reads the 2-byte version as one big-endian uint16 and
subtracts FVNO_BASE=0x0500, so the on-disk bytes are the two separate bytes
0x05, 0x04 — NOT a big-endian uint16 encoding of the numbers 5 and 4).
"""

from __future__ import annotations

import struct

# Server principal realm MIT krb5 uses for non-ticket "config entries"
# (fast_avail, pa_type, ...) — see ccache.py's own docstring.
CONFIG_ENTRY_REALM = "X-CACHECONF:"


def _pack_data(value: bytes) -> bytes:
    return struct.pack(">I", len(value)) + value


def _pack_principal(realm: str, components: list[str]) -> bytes:
    out = struct.pack(">I", 1)  # name type: KRB5_NT_PRINCIPAL (unchecked by ccache.py)
    out += struct.pack(">I", len(components))
    out += _pack_data(realm.encode())
    for component in components:
        out += _pack_data(component.encode())
    return out


def _pack_keyblock() -> bytes:
    # enctype 18 = aes256-cts-hmac-sha1-96; contents are never read by
    # ccache.py, so a fixed dummy key is fine.
    return struct.pack(">H", 18) + _pack_data(b"\x00" * 32)


def _pack_credential(
    *,
    client_realm: str,
    client_components: list[str],
    server_realm: str,
    server_components: list[str],
    authtime: int,
    starttime: int,
    endtime: int,
    renew_till: int,
    ticket: bytes = b"",
) -> bytes:
    out = _pack_principal(client_realm, client_components)
    out += _pack_principal(server_realm, server_components)
    out += _pack_keyblock()
    out += struct.pack(">IIII", authtime, starttime, endtime, renew_till)
    out += struct.pack(">B", 0)  # is_skey
    out += struct.pack(">I", 0)  # ticket_flags
    out += struct.pack(">I", 0)  # addresses: count
    out += struct.pack(">I", 0)  # authdata: count
    out += _pack_data(ticket)
    out += _pack_data(b"")  # second_ticket
    return out


def build_ccache(
    *,
    username: str,
    realm: str,
    authtime: int,
    endtime: int,
    renew_till: int = 0,
    include_tgt: bool = True,
) -> bytes:
    """Build a genuine FILE-ccache v4 byte string for tests.

    Includes an X-CACHECONF: config-entry credential (all-zero times, as a
    real MIT ccache carries — see ccache_file_format.rst) ahead of the real
    TGT, so ccache.py's skip-logic is actually exercised rather than merely
    untested. *renew_till* of 0 produces a non-renewable ticket (ccache.py's
    ``renew_until: None`` case). *include_tgt* False omits the
    krbtgt/<realm>@<realm> credential entirely, for exercising
    ccache.py's "no usable TGT" error path.
    """
    version = struct.pack(">BB", 5, 4)
    header_fields = struct.pack(">H", 0)  # zero-length field sequence: no fields
    default_principal = _pack_principal(realm, [username])

    config_entry = _pack_credential(
        client_realm=realm,
        client_components=[username],
        server_realm=CONFIG_ENTRY_REALM,
        server_components=["krb5_ccache_conf_data", "pa_type"],
        authtime=0,
        starttime=0,
        endtime=0,
        renew_till=0,
        ticket=b"1",
    )
    out = version + header_fields + default_principal + config_entry
    if include_tgt:
        out += _pack_credential(
            client_realm=realm,
            client_components=[username],
            server_realm=realm,
            server_components=["krbtgt", realm],
            authtime=authtime,
            starttime=authtime,
            endtime=endtime,
            renew_till=renew_till,
        )
    return out
