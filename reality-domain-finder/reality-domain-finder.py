#!/usr/bin/env python3
"""V1.0.9 交互式查找适合 Xray REALITY 的邻近 TLS 目标域名。"""

from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import json
import re
import shutil
import socket
import statistics
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import unicodedata
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) RealityDomainFinder/1.0"
PUBLIC_IP_URLS = (
    "https://api.ipify.org",
    "https://ifconfig.co/ip",
    "https://icanhazip.com",
)
RIPE_NETWORK_INFO_URL = (
    "https://stat.ripe.net/data/network-info/data.json?resource={ip}"
)
HE_IP_URL = "https://bgp.he.net/ip/{ip}"
HE_CERT_API_URL = "https://bgp.he.net/certs/api/ip-search?ip={prefix}"
DEFAULT_MAINSTREAM_TLDS = frozenset({"com", "cn", "net", "org"})

PROVIDER_OR_DYNAMIC_RE = re.compile(
    r"(?:^|\.)(?:"
    r"synology\.me|myds\.me|quickconnect\.to|myqnapcloud\.com|"
    r"mycloudnas\.com|remotewd\.com|asuscomm\.com|dpdns\.org|"
    r"dynamic\.163data\.com\.cn"
    r")$",
    re.IGNORECASE,
)
SERVICE_LABEL_RE = re.compile(
    r"(?:^|[.-])(?:"
    r"admin|api|auth|dev|imap|internal|intranet|login|mail|nas|oa|"
    r"pop|registry|repo|smtp|staging|test|vpn"
    r")(?:[.-]|$)",
    re.IGNORECASE,
)
SENSITIVE_RE = re.compile(
    r"(?:\.gov(?:\.|$)|bank|payment|police|hospital|rmyy)", re.IGNORECASE
)


@dataclass(frozen=True)
class Candidate:
    hostname: str
    observed_ips: tuple[str, ...]
    score: int


@dataclass(frozen=True)
class TestResult:
    hostname: str
    resolved_ips: tuple[str, ...]
    nearby: bool
    tls13: bool
    verified: bool
    x25519: bool
    h2: bool
    cipher: str
    success: bool
    reason: str
    latency_ms: float | None = None
    stability_attempts: int = 0
    stability_successes: int = 0
    stability_rate: float = 0.0
    latency_median_ms: float | None = None
    latency_average_ms: float | None = None
    latency_max_ms: float | None = None
    latency_jitter_ms: float | None = None


def request_bytes(url: str, timeout: float, headers: dict[str, str] | None = None) -> bytes:
    request_headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    if headers:
        request_headers.update(headers)
    request = urllib.request.Request(url, headers=request_headers)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def request_json(url: str, timeout: float, headers: dict[str, str] | None = None) -> Any:
    return json.loads(request_bytes(url, timeout, headers).decode("utf-8"))


def get_public_ipv4(timeout: float) -> ipaddress.IPv4Address:
    errors: list[str] = []
    for url in PUBLIC_IP_URLS:
        try:
            value = request_bytes(url, timeout).decode("ascii").strip()
            address = ipaddress.ip_address(value)
            if isinstance(address, ipaddress.IPv4Address):
                return address
            errors.append(f"{url}: returned IPv6")
        except Exception as exc:  # Keep fallbacks independent.
            errors.append(f"{url}: {exc}")
    raise RuntimeError("无法获取公网 IPv4：" + "; ".join(errors))


def get_bgp_prefix(address: ipaddress.IPv4Address, timeout: float) -> ipaddress.IPv4Network:
    try:
        data = request_json(RIPE_NETWORK_INFO_URL.format(ip=address), timeout)
        prefix = data.get("data", {}).get("prefix")
        network = ipaddress.ip_network(prefix, strict=False)
        if isinstance(network, ipaddress.IPv4Network) and address in network:
            return network
    except Exception:
        pass

    html = request_bytes(HE_IP_URL.format(ip=address), timeout).decode(
        "utf-8", errors="replace"
    )
    matches = re.findall(r'/net/(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})', html)
    containing: list[ipaddress.IPv4Network] = []
    for value in matches:
        try:
            network = ipaddress.ip_network(value, strict=False)
            if isinstance(network, ipaddress.IPv4Network) and address in network:
                containing.append(network)
        except ValueError:
            continue
    if not containing:
        raise RuntimeError(f"无法确定 {address} 所属的 BGP 前缀")
    return max(containing, key=lambda network: network.prefixlen)


def valid_hostname(value: str) -> str | None:
    value = value.strip().rstrip(".").lower()
    if not value or "*" in value or len(value) > 253:
        return None
    try:
        hostname = value.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    labels = hostname.split(".")
    if len(labels) < 2:
        return None
    for label in labels:
        if not 1 <= len(label) <= 63:
            return None
        if label.startswith("-") or label.endswith("-"):
            return None
        if not re.fullmatch(r"[a-z0-9-]+", label):
            return None
    return hostname


MULTI_LABEL_SUFFIXES = {
    "com.cn",
    "net.cn",
    "org.cn",
    "gov.cn",
    "edu.cn",
    "co.uk",
    "com.au",
    "co.jp",
}


def registrable_label(hostname: str) -> str:
    labels = hostname.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_LABEL_SUFFIXES:
        return labels[-3]
    return labels[-2]


def is_numeric_domain(hostname: str) -> bool:
    """Return True when the main registered-domain label contains only digits."""
    return registrable_label(hostname).isdigit()


NUMERIC_FILTER_LABELS = {
    "none": "不过滤数字",
    "pure": "过滤纯数字主域名",
    "any": "完全过滤包含数字的域名",
}


def should_filter_numeric_domain(hostname: str, mode: str) -> bool:
    if mode == "none":
        return False
    if mode == "pure":
        return is_numeric_domain(hostname)
    if mode == "any":
        return any(character.isdigit() for character in hostname)
    raise ValueError(f"未知的数字过滤模式：{mode}")


def parse_tld_list(value: str) -> frozenset[str]:
    tlds: set[str] = set()
    for item in value.split(","):
        tld = item.strip().lower().lstrip(".")
        if not tld:
            continue
        if not re.fullmatch(r"[a-z0-9-]{2,63}", tld):
            raise ValueError(f"无效的顶级域名：{item.strip()}")
        tlds.add(tld)
    if not tlds:
        raise ValueError("主流顶级域名列表不能为空")
    return frozenset(tlds)


def has_allowed_tld(hostname: str, allowed_tlds: frozenset[str]) -> bool:
    return hostname.rsplit(".", 1)[-1] in allowed_tlds


def candidate_score(hostname: str, observed_ips: Iterable[str], network: ipaddress.IPv4Network) -> int:
    labels = hostname.split(".")
    score = 0
    if hostname.startswith("www."):
        score += 35
    if len(labels) == 2:
        score += 25
    elif len(labels) == 3:
        score += 15
    if hostname.endswith((".com", ".com.cn", ".cn", ".net", ".org.cn")):
        score += 10
    if hostname.endswith(".edu.cn"):
        score -= 10
    for value in observed_ips:
        try:
            if ipaddress.ip_address(value) in network:
                score += 15
                break
        except ValueError:
            continue
    return score


def fetch_candidates(
    network: ipaddress.IPv4Network,
    timeout: float,
    numeric_filter: str = "any",
    allowed_tlds: frozenset[str] | None = DEFAULT_MAINSTREAM_TLDS,
) -> list[Candidate]:
    encoded_prefix = urllib.parse.quote(str(network), safe="")
    referer = f"https://bgp.he.net/net/{network}#_SearchTab"
    data = request_json(
        HE_CERT_API_URL.format(prefix=encoded_prefix),
        timeout,
        headers={"Accept": "application/json", "Referer": referer},
    )
    entries = data.get("entries")
    if not isinstance(entries, list):
        raise RuntimeError("证书查询接口没有返回域名记录")

    by_hostname: dict[str, set[str]] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        observed_ip = str(entry.get("ip", "")).strip()
        hostnames = entry.get("hostnames", [])
        if not isinstance(hostnames, list):
            continue
        for raw_hostname in hostnames:
            hostname = valid_hostname(str(raw_hostname))
            if not hostname:
                continue
            if PROVIDER_OR_DYNAMIC_RE.search(hostname):
                continue
            if SERVICE_LABEL_RE.search(hostname) or SENSITIVE_RE.search(hostname):
                continue
            if should_filter_numeric_domain(hostname, numeric_filter):
                continue
            if allowed_tlds is not None and not has_allowed_tld(hostname, allowed_tlds):
                continue
            by_hostname.setdefault(hostname, set()).add(observed_ip)

    candidates = [
        Candidate(
            hostname=hostname,
            observed_ips=tuple(sorted(ips)),
            score=candidate_score(hostname, ips, network),
        )
        for hostname, ips in by_hostname.items()
    ]
    candidates.sort(key=lambda item: (-item.score, item.hostname))
    return candidates


def resolve_ipv4(hostname: str, timeout: float) -> tuple[str, ...]:
    if shutil.which("getent"):
        try:
            completed = subprocess.run(
                ["getent", "ahostsv4", hostname],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            addresses = {
                line.split()[0]
                for line in completed.stdout.splitlines()
                if line.split()
            }
            valid = sorted(
                str(ipaddress.ip_address(value))
                for value in addresses
                if isinstance(ipaddress.ip_address(value), ipaddress.IPv4Address)
            )
            return tuple(valid)
        except (subprocess.TimeoutExpired, ValueError):
            return ()

    try:
        results = socket.getaddrinfo(hostname, 443, socket.AF_INET, socket.SOCK_STREAM)
    except OSError:
        return ()
    return tuple(sorted({item[4][0] for item in results}))


def extract_failure(output: str, returncode: int) -> str:
    checks = (
        (r"alert protocol version", "目标拒绝 TLS 1.3"),
        (r"hostname mismatch", "证书与域名不匹配"),
        (r"certificate verify failed", "证书验证失败"),
        (r"connection refused", "连接被拒绝"),
        (r"no route to host", "没有可用路由"),
        (r"timed? out", "连接超时"),
        (r"Cipher is \(NONE\)", "TLS 握手失败"),
    )
    for pattern, reason in checks:
        if re.search(pattern, output, re.IGNORECASE):
            return reason
    return f"OpenSSL 退出状态为 {returncode}"


def test_candidate(
    candidate: Candidate,
    network: ipaddress.IPv4Network,
    timeout: float,
    require_nearby: bool,
) -> TestResult:
    hostname = candidate.hostname
    resolved_ips = resolve_ipv4(hostname, timeout)
    nearby = any(ipaddress.ip_address(value) in network for value in resolved_ips)
    if not resolved_ips:
        return TestResult(hostname, (), False, False, False, False, False, "", False, "DNS 解析失败")
    if require_nearby and not nearby:
        return TestResult(
            hostname,
            resolved_ips,
            False,
            False,
            False,
            False,
            False,
            "",
            False,
            "DNS 当前已不指向 VPS 所在前缀",
        )

    command = [
        "openssl",
        "s_client",
        "-connect",
        f"{hostname}:443",
        "-servername",
        hostname,
        "-tls1_3",
        "-verify_hostname",
        hostname,
        "-verify_return_error",
        "-alpn",
        "h2",
    ]
    started_at = time.monotonic()
    try:
        completed = subprocess.run(
            command,
            input=b"",
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        latency_ms = (time.monotonic() - started_at) * 1000
        return TestResult(
            hostname,
            resolved_ips,
            nearby,
            False,
            False,
            False,
            False,
            "",
            False,
            "OpenSSL 检测超时",
            latency_ms=latency_ms,
        )
    latency_ms = (time.monotonic() - started_at) * 1000

    output = (completed.stdout + completed.stderr).decode("utf-8", errors="replace")
    tls13 = bool(
        re.search(r"(?:New,\s*)?TLSv1\.3|Protocol version:\s*TLSv1\.3", output)
    )
    verified = bool(
        re.search(r"Verification:\s*OK|Verify return code:\s*0\s*\(ok\)", output)
    ) and not bool(re.search(r"hostname mismatch|verification error", output, re.IGNORECASE))
    x25519 = bool(re.search(r"(?:Server|Peer) Temp Key:\s*X25519", output))
    h2 = bool(re.search(r"(?:Negotiated )?ALPN protocol:\s*h2", output, re.IGNORECASE))
    cipher_match = re.search(
        r"(?:Cipher is|Ciphersuite:)\s*(TLS_[A-Z0-9_]+)", output
    )
    cipher = cipher_match.group(1) if cipher_match else ""
    success = tls13 and verified and x25519 and bool(cipher)
    reason = "检测通过" if success else extract_failure(output, completed.returncode)
    return TestResult(
        hostname,
        resolved_ips,
        nearby,
        tls13,
        verified,
        x25519,
        h2,
        cipher,
        success,
        reason,
        latency_ms=latency_ms,
    )


def evaluate_candidate(
    candidate: Candidate,
    network: ipaddress.IPv4Network,
    timeout: float,
    require_nearby: bool,
    stability_attempts: int,
) -> TestResult:
    first_result = test_candidate(candidate, network, timeout, require_nearby)
    if not first_result.success:
        return first_result

    probe_results = [first_result]
    for _ in range(stability_attempts - 1):
        probe_results.append(
            test_candidate(candidate, network, timeout, require_nearby)
        )

    successful_results = [result for result in probe_results if result.success]
    successful_latencies = [
        result.latency_ms
        for result in successful_results
        if result.latency_ms is not None
    ]
    success_count = len(successful_results)
    success_rate = success_count / stability_attempts

    if successful_latencies:
        median_ms = statistics.median(successful_latencies)
        average_ms = statistics.mean(successful_latencies)
        maximum_ms = max(successful_latencies)
        jitter_ms = (
            statistics.pstdev(successful_latencies)
            if len(successful_latencies) > 1
            else 0.0
        )
    else:
        median_ms = average_ms = maximum_ms = jitter_ms = None

    reason = "基础条件通过"
    return replace(
        first_result,
        reason=reason,
        stability_attempts=stability_attempts,
        stability_successes=success_count,
        stability_rate=success_rate,
        latency_median_ms=median_ms,
        latency_average_ms=average_ms,
        latency_max_ms=maximum_ms,
        latency_jitter_ms=jitter_ms,
    )


def print_result(result: TestResult) -> None:
    status = "通过" if result.success else "失败"
    flags = (
        f"TLS1.3={'是' if result.tls13 else '否'} "
        f"X25519={'是' if result.x25519 else '否'} "
        f"H2={'是' if result.h2 else '否'} "
        f"证书={'是' if result.verified else '否'} "
        f"邻近={'是' if result.nearby else '否'}"
    )
    if result.stability_attempts:
        flags += (
            f" 握手成功率={result.stability_successes}/{result.stability_attempts}"
            f"({result.stability_rate * 100:.0f}%)"
        )
    if result.latency_median_ms is not None:
        flags += f" 中位延迟={result.latency_median_ms:.0f}ms"
    print(f"[{status}] {result.hostname:<45} {flags}  {result.reason}")


def display_width(value: str) -> int:
    return sum(
        2 if unicodedata.east_asian_width(character) in {"W", "F"} else 1
        for character in value
    )


def pad_display(value: str, width: int, alignment: str = "left") -> str:
    padding = max(0, width - display_width(value))
    if alignment == "right":
        return " " * padding + value
    if alignment == "center":
        left_padding = padding // 2
        return " " * left_padding + value + " " * (padding - left_padding)
    return value + " " * padding


def build_aligned_table(
    headers: tuple[str, ...],
    rows: list[tuple[str, ...]],
    alignments: tuple[str, ...],
) -> list[str]:
    widths = [
        max(display_width(header), *(display_width(row[index]) for row in rows))
        for index, header in enumerate(headers)
    ]

    def format_row(row: tuple[str, ...], row_alignments: tuple[str, ...]) -> str:
        return "  ".join(
            pad_display(value, widths[index], row_alignments[index])
            for index, value in enumerate(row)
        )

    header_line = format_row(headers, tuple("left" for _ in headers))
    separator_line = "  ".join("-" * width for width in widths)
    data_lines = [format_row(row, alignments) for row in rows]
    return [header_line, separator_line, *data_lines]


def format_milliseconds(value: float | None) -> str:
    return "-" if value is None else f"{value:.1f}"


def write_output(path: Path, results: list[TestResult], public_ip: str, prefix: str) -> None:
    headers = (
        "域名:端口",
        "H2",
        "加密套件",
        "握手成功率",
        "中位延迟ms",
        "平均延迟ms",
        "最大延迟ms",
        "延迟波动ms",
        "当前解析IPv4",
    )
    alignments = (
        "left",
        "center",
        "left",
        "right",
        "right",
        "right",
        "right",
        "right",
        "left",
    )
    rows = [
        (
            f"{result.hostname}:443",
            "是" if result.h2 else "否",
            result.cipher,
            f"{result.stability_rate * 100:.0f}%",
            format_milliseconds(result.latency_median_ms),
            format_milliseconds(result.latency_average_ms),
            format_milliseconds(result.latency_max_ms),
            format_milliseconds(result.latency_jitter_ms),
            ",".join(result.resolved_ips),
        )
        for result in results
    ]
    table_lines = build_aligned_table(headers, rows, alignments)
    lines = [
        f"# VPS 公网 IPv4：{public_ip}",
        f"# BGP 前缀：{prefix}",
        "# 握手成功率与延迟仅供参考，不参与基础入选判断",
        *table_lines,
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def load_history(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"format_version": 1, "entries": {}}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"无法读取历史标记文件 {path}：{exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("entries"), dict):
        raise RuntimeError(f"历史标记文件 {path} 格式无效")
    return data


def save_history(path: Path, history: dict[str, Any]) -> None:
    history["format_version"] = 1
    history["updated_at"] = datetime.now(timezone.utc).isoformat()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = path.with_name(path.name + ".tmp")
    temporary_path.write_text(
        json.dumps(history, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary_path.replace(path)


def mark_checked(
    history: dict[str, Any],
    result: TestResult,
    network: ipaddress.IPv4Network,
) -> None:
    entries = history.setdefault("entries", {})
    entries[result.hostname] = {
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "prefix": str(network),
        "success": result.success,
        "tls13": result.tls13,
        "x25519": result.x25519,
        "h2": result.h2,
        "certificate_verified": result.verified,
        "nearby": result.nearby,
        "cipher": result.cipher,
        "resolved_ips": list(result.resolved_ips),
        "reason": result.reason,
        "handshake_attempts": result.stability_attempts,
        "handshake_successes": result.stability_successes,
        "handshake_success_rate": result.stability_rate,
        "latency_median_ms": result.latency_median_ms,
        "latency_average_ms": result.latency_average_ms,
        "latency_max_ms": result.latency_max_ms,
        "latency_jitter_ms": result.latency_jitter_ms,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="交互式查找邻近 VPS、支持 TLS 1.3/X25519 的 REALITY 目标域名。"
    )
    parser.add_argument("--prefix", help="手动指定 BGP 前缀，例如 203.0.113.0/24")
    parser.add_argument("--count", type=int, default=5, help="至少需要找到的合格域名数量，默认 5")
    parser.add_argument("--batch-size", type=int, default=10, help="每批并发检测数量，默认 10")
    parser.add_argument("--max-candidates", type=int, default=200, help="最多检测的候选数量，默认 200")
    parser.add_argument("--timeout", type=float, default=10.0, help="单次请求或检测超时秒数，默认 10")
    parser.add_argument(
        "--handshake-attempts",
        dest="stability_attempts",
        metavar="次数",
        type=int,
        default=5,
        help="每个基础通过域名的总握手检测次数，仅作参考，默认 5",
    )
    parser.add_argument("--allow-off-prefix", action="store_true", help="允许当前 DNS 不在 VPS 前缀内")
    parser.add_argument(
        "--numeric-filter",
        choices=tuple(NUMERIC_FILTER_LABELS),
        default="any",
        help="数字域名过滤模式：none 不过滤、pure 过滤纯数字、any 过滤任何数字，默认 any",
    )
    parser.add_argument("--allow-all-tlds", action="store_true", help="关闭主流顶级域名过滤，允许所有顶级域名")
    parser.add_argument("--mainstream-tlds", default="com,cn,net,org", help="允许的主流顶级域名，逗号分隔，默认 com,cn,net,org")
    parser.add_argument("--history-file", default="/var/log/reality-domain-finder/reality-domain-history.json", help="历史标记文件，默认 /var/log/reality-domain-finder/reality-domain-history.json")
    parser.add_argument("--recheck", action="store_true", help="重新验证历史文件中已经标记的域名")
    parser.add_argument("--output", default="/var/log/reality-domain-finder/reality-domains.txt", help="结果文件，默认 /var/log/reality-domain-finder/reality-domains.txt")
    parser.add_argument("--non-interactive", action="store_true", help="跳过交互向导，直接使用参数或默认值")
    return parser.parse_args()


def ask_text(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    value = input(f"{prompt}{suffix}：").strip()
    return value or default


def ask_positive_int(prompt: str, default: int) -> int:
    while True:
        value = ask_text(prompt, str(default))
        try:
            number = int(value)
            if number > 0:
                return number
        except ValueError:
            pass
        print("请输入大于 0 的整数。")


def ask_positive_float(prompt: str, default: float) -> float:
    while True:
        value = ask_text(prompt, f"{default:g}")
        try:
            number = float(value)
            if number > 0:
                return number
        except ValueError:
            pass
        print("请输入大于 0 的数字。")


def ask_yes_no(prompt: str, default: bool = True) -> bool:
    hint = "Y/n" if default else "y/N"
    while True:
        value = input(f"{prompt} [{hint}]：").strip().lower()
        if not value:
            return default
        if value in {"y", "yes", "是", "好", "确认"}:
            return True
        if value in {"n", "no", "否", "不"}:
            return False
        print("请输入 y 或 n。")


def ask_numeric_filter(default: str = "any") -> str:
    choices = {"1": "none", "2": "pure", "3": "any"}
    default_choice = {value: key for key, value in choices.items()}[default]
    print("数字域名过滤方式：")
    print("  1. 不过滤数字")
    print("  2. 过滤纯数字主域名")
    print("  3. 完全过滤包含数字的域名")
    while True:
        choice = input(f"请选择 [{default_choice}]：").strip() or default_choice
        if choice in choices:
            return choices[choice]
        print("请输入 1、2 或 3。")


def print_default_config(args: argparse.Namespace) -> None:
    print("\n选项 1 默认参数配置：")
    print("  自动检测 BGP 前缀：是")
    print(f"  合格数量下限：{args.count}")
    print(f"  每批数量：{args.batch_size}")
    print(f"  最大候选：{args.max_candidates}")
    print(f"  检测超时：{args.timeout:g} 秒")
    print(f"  握手检测次数：{args.stability_attempts}（仅作参考）")
    print(f"  强制邻近：{'是' if not args.allow_off_prefix else '否'}")
    print(f"  数字过滤：{NUMERIC_FILTER_LABELS[args.numeric_filter]}")
    print(f"  主流顶级域名过滤：{'是' if not args.allow_all_tlds else '否'}")
    if not args.allow_all_tlds:
        print(f"  允许的顶级域名：{args.mainstream_tlds}")
    print(f"  跳过历史已验证域名：{'是' if not args.recheck else '否'}")
    print(f"  历史文件：{args.history_file}")
    print(f"  结果文件：{args.output}")


def interactive_setup(args: argparse.Namespace) -> argparse.Namespace | None:
    if args.non_interactive or not sys.stdin.isatty():
        return args

    print("=" * 66)
    print(" REALITY 邻近目标域名查找器 V1.0.9")
    print(" 自动获取 VPS IP 和 BGP 前缀，并分批检测 TLS 1.3/X25519/H2")
    print("=" * 66)
    print_default_config(args)
    print("\n请选择运行方式：")
    print("  1. 使用全部默认参数，一键开始")
    print("  2. 自定义参数")
    while True:
        choice = input("请输入选项 [1]：").strip()
        if choice in {"", "1"}:
            print("\n已选择默认参数，开始检测……\n")
            return args
        if choice == "2":
            break
        print("请输入 1 或 2。")

    print("\n进入自定义参数设置。直接按回车可使用方括号中的默认值。\n")

    auto_detect_prefix = ask_yes_no("是否自动检测 BGP 前缀", True)
    if auto_detect_prefix:
        args.prefix = None
    else:
        while True:
            prefix_value = ask_text("请输入 BGP 前缀", args.prefix or "")
            if prefix_value:
                args.prefix = prefix_value
                break
            print("手动模式下 BGP 前缀不能为空。")
    args.count = ask_positive_int("至少需要找到多少个合格域名", args.count)
    args.batch_size = ask_positive_int("每批并发检测多少个域名", args.batch_size)
    args.max_candidates = ask_positive_int("最多检测多少个候选域名", args.max_candidates)
    args.timeout = ask_positive_float("单个域名检测超时（秒）", args.timeout)
    args.stability_attempts = ask_positive_int(
        "每个基础通过域名总共检测多少次握手（仅作参考）",
        args.stability_attempts,
    )
    require_nearby = ask_yes_no("是否要求域名当前仍解析到 VPS 所在前缀", not args.allow_off_prefix)
    args.allow_off_prefix = not require_nearby
    args.numeric_filter = ask_numeric_filter(args.numeric_filter)
    filter_mainstream_tlds = ask_yes_no("是否只允许主流顶级域名", not args.allow_all_tlds)
    args.allow_all_tlds = not filter_mainstream_tlds
    if filter_mainstream_tlds:
        args.mainstream_tlds = ask_text(
            "允许的顶级域名（使用英文逗号分隔）",
            args.mainstream_tlds,
        )
    skip_checked = ask_yes_no("是否跳过历史中已经验证过的域名", not args.recheck)
    args.recheck = not skip_checked
    args.history_file = ask_text("历史标记文件", args.history_file)
    args.output = ask_text("结果输出文件", args.output)

    print("\n当前设置：")
    print(f"  自动检测 BGP 前缀：{'是' if args.prefix is None else '否'}")
    if args.prefix is not None:
        print(f"  BGP 前缀：{args.prefix}")
    print(f"  合格数量下限：{args.count}")
    print(f"  每批数量：{args.batch_size}")
    print(f"  最大候选：{args.max_candidates}")
    print(f"  检测超时：{args.timeout:g} 秒")
    print(f"  握手检测次数：{args.stability_attempts}（仅作参考）")
    print(f"  强制邻近：{'是' if not args.allow_off_prefix else '否'}")
    print(f"  数字过滤：{NUMERIC_FILTER_LABELS[args.numeric_filter]}")
    print(f"  主流顶级域名过滤：{'是' if not args.allow_all_tlds else '否'}")
    if not args.allow_all_tlds:
        print(f"  允许的顶级域名：{args.mainstream_tlds}")
    print(f"  跳过历史已验证域名：{'是' if not args.recheck else '否'}")
    print(f"  历史文件：{args.history_file}")
    print(f"  输出文件：{args.output}\n")
    if not ask_yes_no("确认开始检测", True):
        print("已取消。")
        return None
    print()
    return args


def main() -> int:
    try:
        args = interactive_setup(parse_args())
    except (EOFError, KeyboardInterrupt):
        print("\n操作已取消。")
        return 130
    if args is None:
        return 0
    if (
        args.count < 1
        or args.batch_size < 1
        or args.max_candidates < 1
        or args.timeout <= 0
        or args.stability_attempts < 1
    ):
        print("目标数量、每批数量、最大候选数、超时和握手检测次数必须大于 0。", file=sys.stderr)
        return 2
    try:
        allowed_tlds = (
            None
            if args.allow_all_tlds
            else parse_tld_list(args.mainstream_tlds)
        )
    except ValueError as exc:
        print(f"顶级域名设置错误：{exc}", file=sys.stderr)
        return 2
    if not shutil.which("openssl"):
        print("系统中没有找到 openssl，请先安装。", file=sys.stderr)
        return 2

    history_path = Path(args.history_file).expanduser()
    try:
        history = load_history(history_path)
    except RuntimeError as exc:
        print(f"历史标记加载失败：{exc}", file=sys.stderr)
        return 1

    try:
        public_ip = get_public_ipv4(args.timeout)
        if args.prefix:
            network = ipaddress.ip_network(args.prefix, strict=False)
            if not isinstance(network, ipaddress.IPv4Network):
                raise ValueError("目前只支持 IPv4 前缀")
        else:
            network = get_bgp_prefix(public_ip, args.timeout)

        print(f"VPS 公网 IPv4：{public_ip}")
        print(f"BGP 前缀      ：{network}")
        if public_ip not in network:
            print("警告：手动指定的前缀不包含当前 VPS 公网 IP。")
        print("正在从 bgp.he.net 获取证书域名……")
        candidates = fetch_candidates(
            network,
            args.timeout,
            numeric_filter=args.numeric_filter,
            allowed_tlds=allowed_tlds,
        )
    except (RuntimeError, ValueError, urllib.error.URLError, json.JSONDecodeError) as exc:
        print(f"域名发现失败：{exc}", file=sys.stderr)
        print("如果自动检测失败，请使用 --prefix 手动指定 VPS 前缀。", file=sys.stderr)
        return 1

    if not candidates:
        print("该前缀没有找到可用的证书域名。", file=sys.stderr)
        return 1

    history_entries = history.get("entries", {})
    skipped_history = 0
    if not args.recheck:
        before_history_filter = len(candidates)
        candidates = [
            candidate
            for candidate in candidates
            if candidate.hostname not in history_entries
        ]
        skipped_history = before_history_filter - len(candidates)

    print(f"数字域名过滤：{NUMERIC_FILTER_LABELS[args.numeric_filter]}")
    if allowed_tlds is None:
        print("主流后缀过滤  ：关闭，允许所有顶级域名")
    else:
        print(f"主流后缀过滤  ：开启，仅允许 {','.join(sorted(allowed_tlds))}")
    print(f"历史标记文件  ：{history_path.resolve()}")
    if args.recheck:
        print("历史跳过      ：关闭，本次允许重新验证")
    else:
        print(f"历史跳过      ：开启，已跳过 {skipped_history} 个域名")

    if not candidates:
        print("所有候选域名都已在历史中标记，没有需要重复验证的域名。", file=sys.stderr)
        print("可在自定义模式关闭历史跳过，或使用 --recheck。", file=sys.stderr)
        return 1

    candidates = candidates[: args.max_candidates]
    print(f"候选域名      ：{len(candidates)} 个（每批检测 {args.batch_size} 个）\n")

    core_results: list[TestResult] = []
    tested = 0
    for offset in range(0, len(candidates), args.batch_size):
        batch = candidates[offset : offset + args.batch_size]
        batch_number = offset // args.batch_size + 1
        print(f"--- 第 {batch_number} 批：{len(batch)} 个候选 ---")
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(batch)) as executor:
            futures = [
                executor.submit(
                    evaluate_candidate,
                    candidate,
                    network,
                    args.timeout,
                    not args.allow_off_prefix,
                    args.stability_attempts,
                )
                for candidate in batch
            ]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                print_result(result)
                tested += 1
                mark_checked(history, result, network)
                try:
                    save_history(history_path, history)
                except OSError as exc:
                    print(f"无法保存历史标记文件：{exc}", file=sys.stderr)
                    return 1
                if result.success:
                    core_results.append(result)
        print()
        if len(core_results) >= args.count:
            break

    selected = sorted(
        core_results,
        key=lambda result: (
            not result.h2,
            -result.stability_rate,
            result.latency_median_ms
            if result.latency_median_ms is not None
            else float("inf"),
            result.hostname,
        ),
    )

    print(
        f"已检测 {tested} 个候选，最低目标为 {args.count} 个，"
        f"实际找到 {len(core_results)} 个核心条件合格的目标。"
    )
    if not selected:
        print("没有找到兼容的目标域名。", file=sys.stderr)
        return 1

    output_path = Path(args.output).expanduser()
    write_output(output_path, selected, str(public_ip), str(network))
    print("\n推荐目标：")
    for index, result in enumerate(selected, 1):
        print(
            f"{index}. {result.hostname}:443  "
            f"H2={'是' if result.h2 else '否'}  "
            f"握手成功率={result.stability_successes}/{result.stability_attempts} "
            f"中位延迟={result.latency_median_ms:.0f}ms  {result.cipher}"
        )
    print(f"\n结果已保存到：{output_path.resolve()}")
    print("\n排名第一的技术候选配置：")
    print(f"  dest：{selected[0].hostname}:443")
    print(f"  serverNames：{selected[0].hostname}")
    print(f"  客户端 serverName：{selected[0].hostname}")
    print("\n注意：基础条件决定是否入选；握手成功率和延迟仅供参考并影响推荐排序。")
    print("域名信誉和内容质量仍需人工确认。")
    return 0 if len(selected) >= args.count else 3


if __name__ == "__main__":
    raise SystemExit(main())
