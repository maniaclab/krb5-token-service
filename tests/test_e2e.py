"""End-to-end test against a real deployment — never faked.

Requires a real deployed krb5-token-service (with real kinit and real
connectivity to a CERN KDC), a real af-mcp-broker minting AF Broker Identity
Tokens, and a real CERN password for a real CERN account. None of that can
be faked without defeating the point of an e2e test, so this module is
skipped unless explicitly opted into:

    KRB5_E2E=1 \\
    KRB5_TOKEN_SERVICE_URL=https://krb5-token.af.uchicago.edu \\
    AF_BROKER_IDENTITY_TOKEN=<freshly-minted broker token> \\
    KRB5_E2E_USERNAME=<real CERN username> \\
    KRB5_E2E_PASSWORD=<real CERN password> \\
    pixi run test

The broker token must be freshly minted (they are short-lived) with
aud=krb5-token-service.
"""

from __future__ import annotations

import base64
import os

import httpx
import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("KRB5_E2E") != "1",
    reason="requires a real deployment, broker, and CERN password; set KRB5_E2E=1 to run",
)


async def test_mint_ticket_against_real_service() -> None:
    base_url = os.environ["KRB5_TOKEN_SERVICE_URL"]
    broker_token = os.environ["AF_BROKER_IDENTITY_TOKEN"]
    username = os.environ["KRB5_E2E_USERNAME"]

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{base_url}/v1/mint",
            headers={"Authorization": f"Bearer {broker_token}"},
            json={
                "username": username,
                "password": os.environ["KRB5_E2E_PASSWORD"],
            },
            timeout=60.0,
        )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["ccache_b64"]
    assert body["principal"] == f"{username}@CERN.CH"
    assert body["realm"] == "CERN.CH"
    assert body["expires_at"]
    assert "renew_until" in body  # present when the KDC granted a renewable ticket

    # The returned bytes must be a real ccache a real klist can read — not
    # just base64 that happens to decode.
    ccache_bytes = base64.b64decode(body["ccache_b64"])
    assert ccache_bytes[:2] == b"\x05\x04"  # FILE-ccache v4 version bytes
