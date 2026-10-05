import ipaddress
import os
import re
import socket
import ssl
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed


# ========================= 扫描配置 =========================

# TCP 端口探测使用更高并发和更短超时；TLS/HTTP 探测使用较低并发和更长超时。
TIMEOUT = 1.5
TCP_TIMEOUT = 0.6
MAX_WORKERS = 512
TCP_MAX_WORKERS = 1024

# 第二步 TLS 探测时使用的 SNI。
TLS_DOMAIN = "www.cloudflare.com"

# 第三步 TLS 握手的 SNI，以及 HTTP 请求的 Host。
HTTP_DOMAIN = "crypto.cloudflare.com"

# 第四步使用自己托管在 Cloudflare 上的域名验证证书。
CUSTOM_DOMAIN = "gcp.xdu.qzz.io"

# 输入、输出配置
IP_RANGES_FILE = "ip.txt"
BESTIP_FILE = "bestip.txt"


def load_ip_ranges(file_path: str = IP_RANGES_FILE) -> list[str]:
    """从文件读取 CIDR IP 段，支持空格或换行分隔；忽略 # 注释。"""
    with open(file_path, encoding="utf-8") as file:
        content = file.read()

    cidr_list = []
    for line in content.splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            cidr_list.extend(line.split())

    if not cidr_list:
        raise ValueError(f"文件 {file_path} 中没有有效的 CIDR IP 段。")

    return cidr_list


def expand_ip_ranges(cidr_list: list[str]) -> list[str]:
    """展开 CIDR IP 段，返回所有可用主机 IP。"""
    ip_list = []
    for cidr in cidr_list:
        network = ipaddress.ip_network(cidr, strict=False)
        ip_list.extend(str(ip) for ip in network.hosts())
    return ip_list


def create_tls_connection(
    ip: str,
    server_name: str,
    timeout: float = TIMEOUT,
) -> ssl.SSLSocket:
    """连接 IP:443 并完成 TLS 握手。"""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    sock = socket.create_connection((ip, 443), timeout=timeout)
    try:
        tls_sock = context.wrap_socket(sock, server_hostname=server_name)
    except Exception:
        sock.close()
        raise

    tls_sock.settimeout(timeout)
    return tls_sock


# ========================= 第一步：TCP 443 探测 =========================


def probe_tcp_443(ip: str) -> bool:
    """探测 IP 的 443 端口是否可以建立 TCP 连接。"""
    try:
        with socket.create_connection((ip, 443), timeout=TCP_TIMEOUT):
            return True
    except OSError:
        return False


def scan_tcp_batch(ip_list: list[str]) -> list[str]:
    """并发执行 TCP 443 探测，返回 443 端口可连接的 IP。"""
    tcp_ips = []

    with ThreadPoolExecutor(max_workers=TCP_MAX_WORKERS) as executor:
        futures = {
            executor.submit(probe_tcp_443, ip): ip
            for ip in ip_list
        }

        for future in as_completed(futures):
            ip = futures[future]
            try:
                if future.result():
                    tcp_ips.append(ip)
                    print(f"[TCP 443] 端口开放: {ip}")
            except Exception:
                pass

    return tcp_ips


# ========================= 第二步：TLS 探测 =========================


def probe_tls(ip: str) -> bool:
    """通过 TCP + TLS 探测 IP，并检查 www.cloudflare.com 的证书。"""
    try:
        with create_tls_connection(ip, TLS_DOMAIN) as tls_sock:
            certificate = tls_sock.getpeercert(binary_form=True)
            return bool(certificate and b"cloudflare" in certificate.lower())
    except (OSError, ssl.SSLError):
        return False


def scan_tls_batch(ip_list: list[str]) -> list[str]:
    """并发执行第二步，返回 TLS 证书探测通过的 IP。"""
    tls_ips = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(probe_tls, ip): ip
            for ip in ip_list
        }

        for future in as_completed(futures):
            ip = futures[future]
            try:
                if future.result():
                    tls_ips.append(ip)
                    print(f"[TLS] 保留 IP: {ip}")
            except Exception:
                pass

    return tls_ips


# ========================= 第三步：HTTP 301 验证 =========================


def probe_http_301(ip: str) -> bool:
    """使用 crypto.cloudflare.com 作为 TLS SNI 和 HTTP Host，严格检查 301。"""
    try:
        with create_tls_connection(ip, HTTP_DOMAIN) as tls_sock:
            request = (
                "GET / HTTP/1.1\r\n"
                f"Host: {HTTP_DOMAIN}\r\n"
                "User-Agent: Mozilla/5.0\r\n"
                "Connection: close\r\n"
                "\r\n"
            ).encode("ascii")
            tls_sock.sendall(request)

            response = b""
            while b"\r\n" not in response and len(response) < 8192:
                chunk = tls_sock.recv(1024)
                if not chunk:
                    break
                response += chunk

            status_line = response.decode("ascii", errors="ignore").split(
                "\r\n", 1
            )[0]
            match = re.match(r"HTTP/\d\.\d\s+(\d{3})(?:\s|$)", status_line)
            return bool(match and match.group(1) == "301")
    except (OSError, ssl.SSLError):
        return False


def scan_http_batch(tls_ips: list[str]) -> list[str]:
    """并发执行第三步，返回 HTTP 状态码为 301 的有效 IP。"""
    valid_ips = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(probe_http_301, ip): ip
            for ip in tls_ips
        }

        for future in as_completed(futures):
            ip = futures[future]
            try:
                if future.result():
                    valid_ips.append(ip)
                    print(f"[HTTP 301] 有效 IP: {ip}")
            except Exception:
                pass

    return valid_ips


# ========================= 第四步：自定义域名证书验证 =========================


def certificate_matches_custom_domain(tls_sock: ssl.SSLSocket) -> bool:
    """检查 TLS 返回证书的 CN 或 SAN 是否包含自定义域名。"""
    certificate = tls_sock.getpeercert(binary_form=True)
    if not certificate:
        return False

    certificate_file = tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".pem",
        encoding="ascii",
        delete=False,
    )
    try:
        certificate_file.write(ssl.DER_cert_to_PEM_cert(certificate))
        certificate_file.close()
        decoded = ssl._ssl._test_decode_cert(certificate_file.name)
    finally:
        certificate_file.close()
        os.unlink(certificate_file.name)

    names = {
        value.lower()
        for name, value in decoded.get("subjectAltName", ())
        if name == "DNS"
    }
    names.update(
        value.lower()
        for group in decoded.get("subject", ())
        for name, value in group
        if name == "commonName"
    )
    return CUSTOM_DOMAIN.lower() in names


def probe_custom_domain(ip: str) -> bool:
    """使用自定义域名作为 TLS SNI，确认返回证书包含该域名。"""
    try:
        with create_tls_connection(ip, CUSTOM_DOMAIN) as tls_sock:
            return certificate_matches_custom_domain(tls_sock)
    except (OSError, ssl.SSLError, ValueError):
        return False


def scan_custom_domain_batch(http_ips: list[str]) -> list[str]:
    """并发执行第四步，返回证书匹配自定义域名的 IP。"""
    valid_ips = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(probe_custom_domain, ip): ip
            for ip in http_ips
        }

        for future in as_completed(futures):
            ip = futures[future]
            try:
                if future.result():
                    valid_ips.append(ip)
                    print(f"[CUSTOM TLS] 证书匹配 {CUSTOM_DOMAIN}: {ip}")
            except Exception:
                pass

    return valid_ips


# ========================= 第五步：保存有效 IP =========================


def save_best_ips(ip_list: list[str], file_path: str) -> None:
    """将有效 IP 保存到 bestip.txt，每行一个并覆盖旧结果。"""
    unique_ips = sorted(set(ip_list))
    with open(file_path, "w", encoding="utf-8", newline="\n") as file:
        for ip in unique_ips:
            file.write(f"{ip}\n")


# ========================= 主流程：五步执行 =========================


def main() -> None:
    cidr_list = load_ip_ranges()
    ip_list = expand_ip_ranges(cidr_list)
    print(f"开始扫描 {len(cidr_list)} 个 IP 段，共 {len(ip_list)} 个 IP...\n")

    # 第一步：先探测 443 端口是否可以建立 TCP 连接。
    tcp_ips = scan_tcp_batch(ip_list)
    print(f"\n第一步完成，443 端口开放 {len(tcp_ips)} 个 IP。")

    # 第二步：TLS 探测，保留 Cloudflare 证书对应的 IP。
    tls_ips = scan_tls_batch(tcp_ips)
    print(f"第二步完成，保留 {len(tls_ips)} 个 IP。")

    # 第三步：TLS SNI 和 HTTP Host 均使用 crypto.cloudflare.com，严格要求返回 301。
    http_ips = scan_http_batch(tls_ips)
    print(f"第三步完成，得到 {len(http_ips)} 个 IP。")

    # 第四步：使用自定义域名 SNI，确认返回证书包含 gcp.xdu.qzz.io。
    valid_ips = scan_custom_domain_batch(http_ips)
    print(f"第四步完成，得到 {len(valid_ips)} 个有效 IP。")

    # 第五步：将最终有效 IP 保存到 bestip.txt。
    save_best_ips(valid_ips, BESTIP_FILE)
    print(f"第五步完成，已保存到 {BESTIP_FILE}。")


if __name__ == "__main__":
    main()
