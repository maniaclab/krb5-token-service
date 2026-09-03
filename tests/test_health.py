"""Tests for GET /healthz."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import httpx


class TestHealthz:
    async def test_healthz_is_200_unconditionally(
        self, client: httpx.AsyncClient
    ) -> None:
        resp = await client.get("/healthz")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}

    async def test_healthz_requires_no_authorization(
        self, client: httpx.AsyncClient
    ) -> None:
        resp = await client.get("/healthz")
        assert resp.status_code == 200
