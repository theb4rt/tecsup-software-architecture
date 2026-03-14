#1. ALTA COHESION

class PortScanner:

    def __init__(self, timeout: float = 1.0):
        self.timeout = timeout

    def scan(self, target: str, ports: list[int]) -> list[int]:
        open_ports = []
        for port in ports:
            if self._is_open(target, port):
                open_ports.append(port)
        return open_ports

    def scan_common_ports(self, target: str) -> list[int]:
        common = [21, 22, 80, 443, 3306, 8080]
        return self.scan(target, common)

    def _is_open(self, target: str, port: int) -> bool:
        sock = socket.socket()
        sock.settimeout(self.timeout)
        result = sock.connect_ex((target, port))
        sock.close()
        return result == 0


#2. BAJA COHESION
class ScannerUtils:

    def scan_port(self, host: str, port: int) -> bool:
        sock = socket.socket()
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0

    def validate_ip(self, ip: str) -> bool:
        parts = ip.split(".")
        return len(parts) == 4

    def send_email(self, to: str, message: str):
        print(f"Email to {to}: {message}")

    def get_timestamp(self) -> str:
        return datetime.now().isoformat()

    def calculate_percentage(self, x: int, total: int) -> float:
        return (x / total) * 100

#3. ALTO ACOPLAMIENTO

class ScannerHighCoupling:

    def __init__(self):
        self.results = []
        self.logger = LoggerHighCoupling()

    def scan(self, target: str, port: int):
        sock = socket.socket()
        is_open = sock.connect_ex((target, port)) == 0
        sock.close()

        self.results.append({"port": port, "open": is_open})
        self.logger._entries.append(f"Scanned {target}:{port}")

    def get_results(self) -> list[dict]:
        return self.results

    def clear_results(self):
        self.results = []
        self.logger._entries.clear()

    def get_log_count(self) -> int:
        return len(self.logger._entries)

    def filter_error_logs(self) -> list[str]:
        return [log for log in self.logger._entries if "error" in log.lower()]

    def modify_last_log(self, new_text: str):
        if self.logger._entries:
            self.logger._entries[-1] = new_text


class LoggerHighCoupling:

    def __init__(self):
        self._entries = []

    def get_logs(self) -> list[str]:
        return self._entries

    def count_logs(self) -> int:
        return len(self._entries)

    def clear_logs(self):
        self._entries.clear()

    def add_batch_logs(self, logs: list[str]):
        self._entries.extend(logs)

#4. BAJO ACOPLAMIENTO


class ScannerLowCoupling:

    def __init__(self, logger: 'Logger'):
        self._logger = logger
        self._scan_count = 0

    def scan(self, target: str, port: int) -> bool:
        sock = socket.socket()
        is_open = sock.connect_ex((target, port)) == 0
        sock.close()

        self._logger.log(f"Scanned {target}:{port} - {'open' if is_open else 'closed'}")
        self._scan_count += 1

        return is_open

    def scan_multiple(self, target: str, ports: list[int]) -> list[int]:
        open_ports = []
        for port in ports:
            if self.scan(target, port):
                open_ports.append(port)
        return open_ports

    def get_scan_count(self) -> int:
        return self._scan_count

    def get_log_summary(self) -> str:
        log_count = self._logger.count()
        return f"Performed {self._scan_count} scans, generated {log_count} log entries"

    def reset(self):
        self._scan_count = 0
        self._logger.log("Scanner reset")


class Logger:

    def __init__(self):
        self.__entries = []

    def log(self, message: str):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.__entries.append(f"[{timestamp}] {message}")

    def get_logs(self) -> list[str]:
        return self.__entries.copy()

    def count(self) -> int:
        return len(self.__entries)

    def clear(self):
        self.__entries.clear()

    def save_to_file(self, filepath: str):
        with open(filepath, 'w') as f:
            f.write('\n'.join(self.__entries))



