"""
MergenSec - Integration Tests
Run: pytest tests/ -v
"""

import asyncio
import pytest
from core.scanner import AsyncScanner
from core.cve_fetcher import fetch_cves


# ─── Scanner Tests ────────────────────────────────────────

class TestAsyncScanner:

    @pytest.mark.asyncio
    async def test_scanner_init(self):
        """AsyncScanner initializes with correct target."""
        scanner = AsyncScanner("127.0.0.1")
        assert scanner.target == "127.0.0.1"

    @pytest.mark.asyncio
    async def test_scan_returns_dict(self):
        """scan() returns a dictionary."""
        scanner = AsyncScanner("127.0.0.1")
        result = await scanner.scan()
        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_scan_has_required_keys(self):
        """scan() result contains host, scan_time, ports."""
        scanner = AsyncScanner("127.0.0.1")
        result = await scanner.scan()
        assert "host" in result
        assert "scan_time" in result
        assert "ports" in result

    @pytest.mark.asyncio
    async def test_scan_ports_is_list(self):
        """ports field is a list."""
        scanner = AsyncScanner("127.0.0.1")
        result = await scanner.scan()
        assert isinstance(result["ports"], list)

    @pytest.mark.asyncio
    async def test_scan_port_has_required_fields(self):
        """Each port entry contains required fields."""
        scanner = AsyncScanner("127.0.0.1")
        result = await scanner.scan()
        if result["ports"]:
            port = result["ports"][0]
            assert "port" in port
            assert "service" in port
            assert "state" in port


# ─── CVE Fetcher Tests ────────────────────────────────────

class TestCVEFetcher:

    @pytest.mark.asyncio
    async def test_fetch_cves_returns_list(self):
        """fetch_cves() returns a list."""
        cves = await fetch_cves("http", "")
        assert isinstance(cves, list)

    @pytest.mark.asyncio
    async def test_fetch_cves_known_service(self):
        """fetch_cves() returns results for a known vulnerable service."""
        cves = await fetch_cves("Apache httpd", "2.4.51")
        assert isinstance(cves, list)

    @pytest.mark.asyncio
    async def test_cve_has_required_fields(self):
        """Each CVE entry contains required fields."""
        cves = await fetch_cves("Apache httpd", "2.4.51")
        if cves:
            cve = cves[0]
            assert "cve_id" in cve
            assert "description" in cve
            assert "cvss_score" in cve
            assert "severity" in cve

    @pytest.mark.asyncio
    async def test_fetch_cves_unknown_service(self):
        """fetch_cves() returns empty list for unknown service."""
        cves = await fetch_cves("xyzunknownservice", "0.0.0")
        assert isinstance(cves, list)


# ─── Integration Test ─────────────────────────────────────

class TestIntegration:

    @pytest.mark.asyncio
    async def test_scanner_to_cve_pipeline(self):
        """Full pipeline: scan localhost then fetch CVEs for first service."""
        scanner = AsyncScanner("127.0.0.1")
        result = await scanner.scan()

        assert isinstance(result, dict)
        assert "ports" in result

        if result["ports"]:
            port = result["ports"][0]
            cves = await fetch_cves(
                service=port.get("service", ""),
                version=port.get("version", "")
            )
            assert isinstance(cves, list)
            print(f"\n[+] Port {port['port']} → {len(cves)} CVEs found")
