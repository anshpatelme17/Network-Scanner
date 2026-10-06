"""LIVE Nmap CVE-script vulnerability adapter (Step 22, defensive only).

Separated from ``vulnerability_scanners`` so the Step 15 fixture modules
keep their no-subprocess guarantee. Fixed server-side invocation only
(see ``NmapVulnScanner``); no user flags, scripts, paths, or commands
can reach the child process. subprocess is used here and ONLY here in
the vulnerability pipeline, always with ``shell=False``, a fixed
executable, typed argv, timeout, output cap, and fixed environment.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess

from app.services.vulnerability_scanners import (
    BASIC_PROFILE,
    NMAP_VULN_SCANNER_NAME,
    STANDARD_PROFILE,
    AssetView,
    ScannedFinding,
    ScannerConfigError,
    ServiceView,
    VulnerabilityScanner,
    VulnScanConfig,
)

NMAP_EXECUTABLE = "nmap"
NMAP_MAX_OUTPUT_BYTES = 8 * 1024 * 1024
NMAP_TIMEOUT_SECONDS = 600
# Fixed minimal environment for the child process (mirrors nmap_runner).
_NMAP_CHILD_ENV = {"PATH": os.defpath, "LC_ALL": "C", "LANG": "C"}

# CVE candidates are extracted from script output; the strict normalizer
# downstream decides what reaches stored findings. Anything else is
# dropped — never severity-guessed, never presented.
_CVE_CANDIDATE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


class NmapVulnError(RuntimeError):
    """The live Nmap vulnerability scan failed in a controlled way."""


class NmapVulnScanner(VulnerabilityScanner):
    """LIVE Nmap CVE-script adapter (Step 22, defensive checks only).

    Fixed server-side invocation: ``nmap -sV -T4 --script "vuln and not
    intrusive" -oX - [-p <stored ports>] <asset IP>`` (STANDARD adds
    ``--version-intensity 5``). Ports come exclusively from stored
    discovered services — never from client input. Only script outputs
    carrying CVE identifiers become findings, with UNKNOWN severity
    (NSE states none) and the raw output excerpt as evidence.
    """

    name = NMAP_VULN_SCANNER_NAME

    @staticmethod
    def is_available() -> bool:
        return shutil.which(NMAP_EXECUTABLE) is not None

    def version_info(self) -> str | None:
        """Query the Nmap binary version (no target, no scan)."""
        if not self.is_available():
            return None
        try:
            completed = subprocess.run(
                [NMAP_EXECUTABLE, "--version"],
                shell=False,
                capture_output=True,
                text=True,
                timeout=10,
                env=_NMAP_CHILD_ENV,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        first_line = (completed.stdout or "").splitlines()
        if not first_line or not first_line[0].startswith("Nmap version "):
            return None
        token = first_line[0].removeprefix("Nmap version ").strip().split()
        return f"nmap {token[0]}" if token else "nmap"

    def configure(self, profile: str) -> VulnScanConfig:
        if profile == BASIC_PROFILE:
            return VulnScanConfig(
                argv_fragments=("-sV", "-T4", "--script", "vuln and not intrusive", "-oX", "-"),
                timeout_seconds=NMAP_TIMEOUT_SECONDS,
            )
        if profile == STANDARD_PROFILE:
            return VulnScanConfig(
                argv_fragments=(
                    "-sV",
                    "--version-intensity",
                    "5",
                    "-T4",
                    "--script",
                    "vuln and not intrusive",
                    "-oX",
                    "-",
                ),
                timeout_seconds=NMAP_TIMEOUT_SECONDS,
            )
        raise ScannerConfigError(f"Profile not supported by {self.name}: {profile!r}.")

    def validate_context(self, asset: AssetView, services: list[ServiceView]) -> None:
        ports = [service.port for service in services if isinstance(service.port, int)]
        if not ports:
            raise ScannerConfigError(
                "No discovered services with ports for this asset; run discovery first. "
                "Open ports are never treated as vulnerabilities by themselves."
            )

    @staticmethod
    def target_ports(services: list[ServiceView], limit: int) -> list[int]:
        """Sorted unique TCP ports from stored services, capped (Step 22)."""
        ports = sorted({service.port for service in services if isinstance(service.port, int)})
        return ports[:limit]

    def execute(self, config: VulnScanConfig, asset: AssetView, services: list[ServiceView]) -> str:
        if not self.is_available():
            raise NmapVulnError("Nmap executable is not available on this host.")
        ports = self.target_ports(services, config.max_ports)
        argv = [
            NMAP_EXECUTABLE,
            *config.argv_fragments,
            "-p",
            ",".join(str(p) for p in ports),
            asset.ip_address,
        ]
        try:
            completed = subprocess.run(
                argv,
                shell=False,
                capture_output=True,
                text=True,
                timeout=config.timeout_seconds,
                env=_NMAP_CHILD_ENV,
            )
        except subprocess.TimeoutExpired:
            raise NmapVulnError(
                f"Nmap vulnerability scan timed out after {config.timeout_seconds} seconds."
            ) from None
        except OSError as exc:
            raise NmapVulnError(f"Could not start Nmap: {exc.strerror or 'OS error'}.") from None
        xml_output = (completed.stdout or "")[:NMAP_MAX_OUTPUT_BYTES]
        if completed.returncode != 0 or "<nmaprun" not in xml_output:
            stderr_tail = (completed.stderr or "").strip()[-300:]
            raise NmapVulnError(
                "Nmap did not produce usable XML output."
                + (f" Scanner reported: {stderr_tail}" if stderr_tail else "")
            )
        return xml_output

    def parse(self, raw: str) -> list[ScannedFinding]:
        """Report CVE-evidenced NSE script outputs only (Step 22)."""
        from xml.etree import ElementTree

        if not raw or not raw.strip():
            raise NmapVulnError("Empty Nmap output.")
        try:
            root = ElementTree.fromstring(raw)
        except ElementTree.ParseError as exc:
            raise NmapVulnError(f"Invalid Nmap XML: {exc}.") from None
        if root.tag != "nmaprun":
            raise NmapVulnError("XML is not Nmap output (missing <nmaprun> root).")
        findings: list[ScannedFinding] = []
        for host_el in root.findall("host"):
            status_el = host_el.find("status")
            state = (status_el.get("state") if status_el is not None else "up") or "up"
            if state != "up":
                continue
            for port_el in host_el.findall("./ports/port"):
                try:
                    port_id = int(port_el.get("portid", ""))
                except (TypeError, ValueError):
                    continue
                if not 0 < port_id <= 65535:
                    continue
                protocol = (port_el.get("protocol") or "tcp").lower()[:8]
                service_el = port_el.find("service")
                service_name = (service_el.get("name") if service_el is not None else None) or None
                product = (service_el.get("product") if service_el is not None else None) or None
                product_version = (
                    service_el.get("version") if service_el is not None else None
                ) or None
                for script_el in port_el.findall("script"):
                    script_id = script_el.get("id") or "unknown-script"
                    output = script_el.get("output") or ""
                    cves = sorted(
                        {match.upper() for match in _CVE_CANDIDATE_PATTERN.findall(output)}
                    )
                    if not cves:
                        continue  # no CVE evidence: not reported, never guessed
                    findings.append(
                        ScannedFinding(
                            scanner_finding_id=f"{script_id}:{port_id}/{protocol}",
                            title=f"[nmap] {script_id} on port {port_id}/{protocol}",
                            description=(
                                "Nmap NSE script reported CVE identifier(s); reported "
                                "output only, not proof of exploitation."
                            ),
                            severity="UNKNOWN",
                            cvss_score=None,
                            cves=tuple(cves),
                            cwe_id=None,
                            port=port_id,
                            protocol=protocol,
                            service_name=service_name,
                            product=product,
                            product_version=product_version,
                            evidence=output.strip()[:2000] or None,
                            solution=None,
                            references=(),
                        )
                    )
        return sorted(findings, key=lambda item: item.scanner_finding_id)

    def scan(
        self, asset: AssetView, services: list[ServiceView], profile: str
    ) -> list[ScannedFinding]:
        config = self.configure(profile)
        self.validate_context(asset, services)
        return self.parse(self.execute(config, asset, services))


__all__ = [
    "NMAP_EXECUTABLE",
    "NMAP_MAX_OUTPUT_BYTES",
    "NMAP_TIMEOUT_SECONDS",
    "NMAP_VULN_SCANNER_NAME",
    "NmapVulnError",
    "NmapVulnScanner",
]
