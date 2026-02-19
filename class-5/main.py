import socket
import ssl
import json
import paramiko
from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol, runtime_checkable
from enum import Enum


class SecurityToolBajaCohesion:

    def __init__(self, target: str):
        self.target = target
        self.open_ports = []
        self.headers_result = {}
        self.ssl_result = {}
        self.report = ""
        self.log_file = "security.log"
        self.ssh_host = "example.com"
        self.ssh_port = 22
        self.ssh_user = "admin"
        self.ssh_pass = "password123"

    def scan_ports(self, ports: list[int]) -> list[int]:
        self.open_ports = []
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((self.target, port))
                if result == 0:
                    self.open_ports.append(port)
                sock.close()
            except socket.error:
                pass
        self._write_log(f"Port scan completed: {self.open_ports}")
        return self.open_ports

    def analyze_headers(self) -> dict:
        import urllib.request
        try:
            response = urllib.request.urlopen(f"https://{self.target}", timeout=5)
            headers = dict(response.headers)
            security_headers = [
                "Content-Security-Policy",
                "Strict-Transport-Security",
                "X-Frame-Options",
                "X-Content-Type-Options",
                "X-XSS-Protection",
            ]
            for h in security_headers:
                self.headers_result[h] = headers.get(h, "MISSING")
        except Exception as e:
            self.headers_result["error"] = str(e)
        self._write_log(f"Header analysis completed: {self.headers_result}")
        return self.headers_result

    def check_ssl(self) -> dict:
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(
                socket.socket(), server_hostname=self.target
            ) as s:
                s.settimeout(5)
                s.connect((self.target, 443))
                cert = s.getpeercert()
                self.ssl_result = {
                    "subject": dict(x[0] for x in cert["subject"]),
                    "issuer": dict(x[0] for x in cert["issuer"]),
                    "expires": cert["notAfter"],
                    "version": s.version(),
                }
        except Exception as e:
            self.ssl_result = {"error": str(e)}
        self._write_log(f"SSL check completed: {self.ssl_result}")
        return self.ssl_result

    def generate_report(self) -> str:
        self.report = f"""
========== SECURITY REPORT ==========
Target: {self.target}
Date: {datetime.now().isoformat()}

[PORT SCAN]
Open ports: {self.open_ports}

[HTTP HEADERS]
{json.dumps(self.headers_result, indent=2)}

[SSL CERTIFICATE]
{json.dumps(self.ssl_result, indent=2)}
======================================
"""
        return self.report

    def send_report_via_ssh(self, remote_path: str) -> bool:
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(self.ssh_host, self.ssh_port, self.ssh_user, self.ssh_pass)
            sftp = client.open_sftp()
            with sftp.file(remote_path, "w") as f:
                f.write(self.report)
            sftp.close()
            client.close()
            return True
        except Exception:
            return False

    def _write_log(self, message: str):
        with open(self.log_file, "a") as f:
            f.write(f"[{datetime.now().isoformat()}] {message}\n")

    def validate_ip(self, ip: str) -> bool:
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        return all(0 <= int(p) <= 255 for p in parts)

    def export_json(self, filepath: str):
        data = {
            "target": self.target,
            "ports": self.open_ports,
            "headers": self.headers_result,
            "ssl": self.ssl_result,
        }
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)


@dataclass
class ScanResult:
    target: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    data: dict = field(default_factory=dict)
    success: bool = True
    error: str | None = None


class PortScanner:

    def __init__(self, timeout: float = 2.0):
        self.timeout = timeout

    def scan(self, target: str, ports: list[int]) -> ScanResult:
        open_ports = []
        for port in ports:
            if self._is_port_open(target, port):
                service = self._identify_service(port)
                open_ports.append({"port": port, "service": service})

        return ScanResult(
            target=target,
            data={"open_ports": open_ports, "total_scanned": len(ports)},
        )

    def _is_port_open(self, target: str, port: int) -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((target, port))
            sock.close()
            return result == 0
        except socket.error:
            return False

    def _identify_service(self, port: int) -> str:
        services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
            443: "HTTPS", 3306: "MySQL", 5432: "PostgreSQL",
            6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
        }
        return services.get(port, "Unknown")

    def get_common_ports(self) -> list[int]:
        return [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 5432, 6379, 8080, 8443]


class HeaderAnalyzer:

    SECURITY_HEADERS = {
        "Content-Security-Policy": "Previene XSS e inyecciones de contenido",
        "Strict-Transport-Security": "Fuerza conexiones HTTPS",
        "X-Frame-Options": "Previene clickjacking",
        "X-Content-Type-Options": "Previene MIME-type sniffing",
        "X-XSS-Protection": "Filtro XSS del navegador (legacy)",
        "Referrer-Policy": "Controla información del referrer",
        "Permissions-Policy": "Controla APIs del navegador",
    }

    def analyze(self, target: str) -> ScanResult:
        import urllib.request
        try:
            response = urllib.request.urlopen(f"https://{target}", timeout=5)
            headers = dict(response.headers)
            findings = self._evaluate_headers(headers)
            score = self._calculate_score(findings)

            return ScanResult(
                target=target,
                data={"findings": findings, "score": score},
            )
        except Exception as e:
            return ScanResult(target=target, success=False, error=str(e))

    def _evaluate_headers(self, headers: dict) -> list[dict]:
        findings = []
        for header, description in self.SECURITY_HEADERS.items():
            value = headers.get(header)
            findings.append({
                "header": header,
                "description": description,
                "present": value is not None,
                "value": value or "MISSING",
                "severity": "HIGH" if value is None else "OK",
            })
        return findings

    def _calculate_score(self, findings: list[dict]) -> float:
        present = sum(1 for f in findings if f["present"])
        return round((present / len(findings)) * 100, 1)


class SSLChecker:

    WEAK_PROTOCOLS = {"TLSv1", "TLSv1.1", "SSLv2", "SSLv3"}

    def check(self, target: str) -> ScanResult:
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(
                socket.socket(), server_hostname=target
            ) as s:
                s.settimeout(5)
                s.connect((target, 443))
                cert = s.getpeercert()
                protocol = s.version()

                cert_info = self._parse_certificate(cert)
                days_left = self._days_until_expiry(cert["notAfter"])
                vulnerabilities = self._check_vulnerabilities(protocol, days_left)

                return ScanResult(
                    target=target,
                    data={
                        "certificate": cert_info,
                        "protocol": protocol,
                        "days_until_expiry": days_left,
                        "vulnerabilities": vulnerabilities,
                    },
                )
        except Exception as e:
            return ScanResult(target=target, success=False, error=str(e))

    def _parse_certificate(self, cert: dict) -> dict:
        return {
            "subject": dict(x[0] for x in cert.get("subject", [])),
            "issuer": dict(x[0] for x in cert.get("issuer", [])),
            "serial": cert.get("serialNumber", "N/A"),
            "not_before": cert.get("notBefore"),
            "not_after": cert.get("notAfter"),
            "san": [entry[1] for entry in cert.get("subjectAltName", [])],
        }

    def _days_until_expiry(self, expiry_str: str) -> int:
        expiry = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
        return (expiry - datetime.now()).days

    def _check_vulnerabilities(self, protocol: str, days_left: int) -> list[str]:
        vulns = []
        if protocol in self.WEAK_PROTOCOLS:
            vulns.append(f"Protocolo débil: {protocol}")
        if days_left < 30:
            vulns.append(f"Certificado expira en {days_left} días")
        if days_left < 0:
            vulns.append("CERTIFICADO EXPIRADO")
        return vulns


class ReportGenerator:

    def generate_text(self, results: list[ScanResult]) -> str:
        lines = [
            "=" * 50,
            "SECURITY ASSESSMENT REPORT",
            f"Generated: {datetime.now().isoformat()}",
            "=" * 50,
        ]
        for result in results:
            lines.append(self._format_section(result))
        return "\n".join(lines)

    def generate_json(self, results: list[ScanResult]) -> str:
        data = {
            "generated_at": datetime.now().isoformat(),
            "results": [
                {
                    "target": r.target,
                    "timestamp": r.timestamp,
                    "success": r.success,
                    "data": r.data,
                    "error": r.error,
                }
                for r in results
            ],
        }
        return json.dumps(data, indent=2)

    def save_to_file(self, content: str, filepath: str):
        with open(filepath, "w") as f:
            f.write(content)

    def _format_section(self, result: ScanResult) -> str:
        if not result.success:
            return f"\n[ERROR] {result.target}: {result.error}\n"
        section = f"\n--- {result.target} ({result.timestamp}) ---\n"
        section += json.dumps(result.data, indent=2)
        return section


class PortScannerAltoAcoplamiento:

    def __init__(self, target: str):
        self.target = target
        self.open_ports = []
        self._internal_state = "scanning"

        self.logger = SecurityLoggerAltoAcoplamiento()

        self.reporter = ReportGeneratorAltoAcoplamiento()

    def scan(self, ports: list[int]) -> list[int]:
        self.open_ports = []
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                if sock.connect_ex((self.target, port)) == 0:
                    self.open_ports.append(port)
                sock.close()
            except socket.error:
                pass

        self.logger._log_entries.append(
            f"Scanned {len(ports)} ports on {self.target}"
        )

        self.reporter.add_port_scan_result(self)

        return self.open_ports


class HeaderAnalyzerAltoAcoplamiento:

    def __init__(self, target: str):
        self.target = target
        self.results = {}

        self.port_scanner = PortScannerAltoAcoplamiento(target)

        self.logger = SecurityLoggerAltoAcoplamiento()

    def analyze(self) -> dict:
        self.port_scanner.scan([80, 443])

        if 443 not in self.port_scanner.open_ports:
            self.results["error"] = "Port 443 not open"
            return self.results

        if self.port_scanner._internal_state != "scanning":
            raise RuntimeError("Scanner in unexpected state")

        import urllib.request
        try:
            response = urllib.request.urlopen(f"https://{self.target}", timeout=5)
            headers = dict(response.headers)
            for h in ["Content-Security-Policy", "Strict-Transport-Security"]:
                self.results[h] = headers.get(h, "MISSING")
        except Exception as e:
            self.results["error"] = str(e)

        self.logger._log_entries.append(f"Headers analyzed for {self.target}")

        self.port_scanner.reporter.add_header_result(self)

        return self.results


class ReportGeneratorAltoAcoplamiento:

    def __init__(self):
        self.sections = []

    def add_port_scan_result(self, scanner: PortScannerAltoAcoplamiento):
        self.sections.append(
            f"Ports on {scanner.target}: {scanner.open_ports} "
            f"(state: {scanner._internal_state})"
        )

    def add_header_result(self, analyzer: HeaderAnalyzerAltoAcoplamiento):
        self.sections.append(
            f"Headers for {analyzer.target}: {analyzer.results}"
        )

    def build(self) -> str:
        return "\n".join(self.sections)


class SecurityLoggerAltoAcoplamiento:

    def __init__(self):
        self._log_entries: list[str] = []

    def get_logs(self) -> list[str]:
        return self._log_entries


class Severity(Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


@dataclass
class Finding:
    category: str
    description: str
    severity: Severity
    details: dict = field(default_factory=dict)


@runtime_checkable
class SecurityScanner(Protocol):
    def scan(self, target: str) -> list[Finding]: ...


@runtime_checkable
class Logger(Protocol):
    def log(self, message: str, level: str = "INFO"): ...


@runtime_checkable
class ReportExporter(Protocol):
    def export(self, findings: list[Finding]) -> str: ...


class ConsoleLogger:

    def log(self, message: str, level: str = "INFO"):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] [{level}] {message}")


class FileLogger:

    def __init__(self, filepath: str = "security.log"):
        self.filepath = filepath

    def log(self, message: str, level: str = "INFO"):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(self.filepath, "a") as f:
            f.write(f"[{timestamp}] [{level}] {message}\n")


class PortScannerBajoAcoplamiento:

    COMMON_PORTS = [21, 22, 80, 443, 3306, 5432, 8080, 8443]

    def __init__(self, logger: Logger, timeout: float = 2.0):
        self._logger = logger
        self._timeout = timeout

    def scan(self, target: str) -> list[Finding]:
        findings = []
        self._logger.log(f"Starting port scan on {target}")

        for port in self.COMMON_PORTS:
            if self._is_port_open(target, port):
                findings.append(Finding(
                    category="PORT_SCAN",
                    description=f"Port {port} is open",
                    severity=Severity.INFO,
                    details={"port": port, "target": target},
                ))

        self._logger.log(f"Port scan complete: {len(findings)} open ports found")
        return findings

    def _is_port_open(self, target: str, port: int) -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self._timeout)
            result = sock.connect_ex((target, port))
            sock.close()
            return result == 0
        except socket.error:
            return False


class HeaderAnalyzerBajoAcoplamiento:

    REQUIRED_HEADERS = [
        ("Content-Security-Policy", Severity.CRITICAL),
        ("Strict-Transport-Security", Severity.CRITICAL),
        ("X-Frame-Options", Severity.WARNING),
        ("X-Content-Type-Options", Severity.WARNING),
        ("Referrer-Policy", Severity.INFO),
    ]

    def __init__(self, logger: Logger):
        self._logger = logger

    def scan(self, target: str) -> list[Finding]:
        import urllib.request
        findings = []
        self._logger.log(f"Analyzing headers for {target}")

        try:
            response = urllib.request.urlopen(f"https://{target}", timeout=5)
            headers = dict(response.headers)

            for header_name, severity in self.REQUIRED_HEADERS:
                if header_name not in headers:
                    findings.append(Finding(
                        category="MISSING_HEADER",
                        description=f"Missing security header: {header_name}",
                        severity=severity,
                        details={"header": header_name, "target": target},
                    ))
        except Exception as e:
            findings.append(Finding(
                category="HEADER_ERROR",
                description=f"Failed to analyze headers: {e}",
                severity=Severity.WARNING,
                details={"target": target, "error": str(e)},
            ))

        self._logger.log(f"Header analysis complete: {len(findings)} issues found")
        return findings


class SSLCheckerBajoAcoplamiento:

    def __init__(self, logger: Logger):
        self._logger = logger

    def scan(self, target: str) -> list[Finding]:
        findings = []
        self._logger.log(f"Checking SSL for {target}")

        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=target) as s:
                s.settimeout(5)
                s.connect((target, 443))
                cert = s.getpeercert()
                protocol = s.version()

                if protocol in {"TLSv1", "TLSv1.1"}:
                    findings.append(Finding(
                        category="WEAK_SSL",
                        description=f"Weak TLS protocol: {protocol}",
                        severity=Severity.CRITICAL,
                        details={"protocol": protocol, "target": target},
                    ))

                expiry = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                days_left = (expiry - datetime.now()).days
                if days_left < 30:
                    findings.append(Finding(
                        category="SSL_EXPIRY",
                        description=f"Certificate expires in {days_left} days",
                        severity=Severity.CRITICAL if days_left < 7 else Severity.WARNING,
                        details={"days_left": days_left, "target": target},
                    ))

        except Exception as e:
            findings.append(Finding(
                category="SSL_ERROR",
                description=f"SSL check failed: {e}",
                severity=Severity.WARNING,
                details={"target": target, "error": str(e)},
            ))

        self._logger.log(f"SSL check complete: {len(findings)} issues found")
        return findings


class TextReportExporter:

    def export(self, findings: list[Finding]) -> str:
        lines = ["=" * 50, "SECURITY ASSESSMENT REPORT", "=" * 50]
        for f in findings:
            icon = {"CRITICAL": "!", "WARNING": "?", "INFO": "*"}
            lines.append(
                f"{icon.get(f.severity.value, '-')} [{f.severity.value}] "
                f"{f.category}: {f.description}"
            )
        lines.append(f"\nTotal findings: {len(findings)}")
        return "\n".join(lines)


class JsonReportExporter:

    def export(self, findings: list[Finding]) -> str:
        data = {
            "generated_at": datetime.now().isoformat(),
            "total_findings": len(findings),
            "findings": [
                {
                    "category": f.category,
                    "description": f.description,
                    "severity": f.severity.value,
                    "details": f.details,
                }
                for f in findings
            ],
        }
        return json.dumps(data, indent=2)


class SecurityAudit:

    def __init__(
        self,
        scanners: list[SecurityScanner],
        exporter: ReportExporter,
        logger: Logger,
    ):
        self._scanners = scanners
        self._exporter = exporter
        self._logger = logger

    def run(self, target: str) -> str:
        all_findings: list[Finding] = []
        self._logger.log(f"Starting security audit on {target}")

        for scanner in self._scanners:
            try:
                findings = scanner.scan(target)
                all_findings.extend(findings)
            except Exception as e:
                self._logger.log(f"Scanner failed: {e}", level="ERROR")
                all_findings.append(Finding(
                    category="SCANNER_ERROR",
                    description=str(e),
                    severity=Severity.WARNING,
                ))

        self._logger.log(
            f"Audit complete: {len(all_findings)} total findings", level="INFO"
        )
        return self._exporter.export(all_findings)


def main():
    logger = ConsoleLogger()

    scanners: list[SecurityScanner] = [
        PortScannerBajoAcoplamiento(logger, timeout=1.0),
        HeaderAnalyzerBajoAcoplamiento(logger),
        SSLCheckerBajoAcoplamiento(logger),
    ]

    exporter = TextReportExporter()

    audit = SecurityAudit(scanners=scanners, exporter=exporter, logger=logger)
    report = audit.run("example.com")
    print(report)


if __name__ == "__main__":
    main()