"""Kerberos ticket minting for the UChicago ATLAS Analysis Facility MCP platform.

Mints Kerberos credential caches for CERN accounts on behalf of the
af-mcp-broker. It receives an identity and the user's CERN password from the
broker, runs ``kinit`` against the CERN realm, and returns the resulting
credential cache (base64-encoded) in the response body. The password lives
only in memory and is zeroed after use; nothing is written to shared storage.
"""
