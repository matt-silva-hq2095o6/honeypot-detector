import ipaddress
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from honeypot_detector.probes.tcp import probe_tcp_syn
from honeypot_detector.probes.ssh import probe_ssh_quirks
from honeypot_detector.probes.http import probe_http_signatures
from honeypot_detector.fingerprints import evaluate_target

DEFAULT_PORTS = [22, 80, 502, 2222, 8080]


class Scanner:
    """Coordinates target expansion, concurrent probe execution, and match scoring."""

    def __init__(self, threads=50, timeout=3.5, ports=None):
        self.threads = max(1, threads)
        self.timeout = timeout
        self.ports = ports or DEFAULT_PORTS

    def _iter_targets(self, raw_targets):
        seen = set()
        for raw in raw_targets:
            raw = raw.strip()
            if not raw:
                continue
            if "/" in raw:
                try:
                    net = ipaddress.ip_network(raw, strict=False)
                    for ip in net.hosts():
                        ip_str = str(ip)
                        if ip_str not in seen:
                            seen.add(ip_str)
                            yield ip_str
                except ValueError:
                    continue
            else:
                try:
                    ipaddress.ip_address(raw)
                    if raw not in seen:
                        seen.add(raw)
                        yield raw
                except ValueError:
                    try:
                        # old fallback name resolution
                        target_ip = socket.gethostbyname(raw)
                        if target_ip not in seen:
                            seen.add(target_ip)
                            yield target_ip
                    except socket.gaierror:
                        pass

    def scan_host(self, host):
        t0 = time.time()
        probe_data = {
            "target": host,
            "open_ports": [],
            "tcp": {},
            "ssh": {},
            "http": {},
        }

        for port in self.ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                res = sock.connect_ex((host, port))
                sock.close()
                if res != 0:
                    continue
            except (socket.error, OSError):
                continue

            probe_data["open_ports"].append(port)

            if port in (22, 2222):
                ssh_meta = probe_ssh_quirks(host, port, timeout=self.timeout)
                if ssh_meta:
                    probe_data["ssh"][port] = ssh_meta

            if port in (80, 8080, 8000, 443):
                http_meta = probe_http_signatures(host, port, timeout=self.timeout)
                if http_meta:
                    probe_data["http"][port] = http_meta

            tcp_meta = probe_tcp_syn(host, port, timeout=self.timeout)
            if tcp_meta:
                probe_data["tcp"][port] = tcp_meta

        if not probe_data["open_ports"]:
            return None

        verdict = evaluate_target(probe_data)
        # print(f"DEBUG: target {host} finished in {time.time() - t0:.2f}s")
        return verdict

    def run(self, raw_targets):
        targets = list(self._iter_targets(raw_targets))
        if not targets:
            return []

        results = []
        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            futures = {pool.submit(self.scan_host, tgt): tgt for tgt in targets}
            for fut in as_completed(futures):
                try:
                    res = fut.result()
                    if res is not None:
                        results.append(res)
                except Exception:
                    pass

        return results
