#!/usr/bin/env python3
"""交互式查找适合 Xray REALITY 的邻近 TLS 目标域名。"""

from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import json
import re
import shutil
import socket
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
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


def fetch_candidates(network: ipaddress.IPv4Network, timeout: float) -> list[Candidate]:
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
    try:
        completed = subprocess.run(
            command,
            input=b"",
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
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
        )

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
    print(f"[{status}] {result.hostname:<45} {flags}  {result.reason}")


def write_output(path: Path, results: list[TestResult], public_ip: str, prefix: str) -> None:
    lines = [
        f"# VPS 公网 IPv4：{public_ip}",
        f"# BGP 前缀：{prefix}",
        "# 域名:端口\tH2\t加密套件\t当前解析 IPv4",
    ]
    for result in results:
        lines.append(
            f"{result.hostname}:443\t{'是' if result.h2 else '否'}\t"
            f"{result.cipher}\t{','.join(result.resolved_ips)}"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="交互式查找邻近 VPS、支持 TLS 1.3/X25519 的 REALITY 目标域名。"
    )
    parser.add_argument("--prefix", help="手动指定 BGP 前缀，例如 203.0.113.0/24")
    parser.add_argument("--count", type=int, default=5, help="需要找到的域名数量，默认 5")
    parser.add_argument("--batch-size", type=int, default=10, help="每批并发检测数量，默认 10")
    parser.add_argument("--max-candidates", type=int, default=200, help="最多检测的候选数量，默认 200")
    parser.add_argument("--timeout", type=float, default=10.0, help="单次请求或检测超时秒数，默认 10")
    parser.add_argument("--allow-off-prefix", action="store_true", help="允许当前 DNS 不在 VPS 前缀内")
    parser.add_argument("--output", default="reality-domains.txt", help="结果文件，默认 reality-domains.txt")
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


def interactive_setup(args: argparse.Namespace) -> argparse.Namespace | None:
    if args.non_interactive or not sys.stdin.isatty():
        return args

    print("=" * 66)
    print(" REALITY 邻近目标域名查找器 v2")
    print(" 自动获取 VPS IP 和 BGP 前缀，并分批检测 TLS 1.3/X25519/H2")
    print("=" * 66)
    print("直接按回车可使用方括号中的默认值。\n")

    prefix_default = args.prefix or "自动检测"
    prefix_value = ask_text("BGP 前缀（输入“自动检测”则自动获取）", prefix_default)
    args.prefix = None if prefix_value in {"自动检测", "自动", "auto", "AUTO"} else prefix_value
    args.count = ask_positive_int("需要找到多少个合格域名", args.count)
    args.batch_size = ask_positive_int("每批并发检测多少个域名", args.batch_size)
    args.max_candidates = ask_positive_int("最多检测多少个候选域名", args.max_candidates)
    args.timeout = ask_positive_float("单个域名检测超时（秒）", args.timeout)
    require_nearby = ask_yes_no("是否要求域名当前仍解析到 VPS 所在前缀", not args.allow_off_prefix)
    args.allow_off_prefix = not require_nearby
    args.output = ask_text("结果输出文件", args.output)

    print("\n当前设置：")
    print(f"  BGP 前缀：{args.prefix or '自动检测'}")
    print(f"  目标数量：{args.count}")
    print(f"  每批数量：{args.batch_size}")
    print(f"  最大候选：{args.max_candidates}")
    print(f"  检测超时：{args.timeout:g} 秒")
    print(f"  强制邻近：{'是' if not args.allow_off_prefix else '否'}")
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
    if args.count < 1 or args.batch_size < 1 or args.max_candidates < 1 or args.timeout <= 0:
        print("目标数量、每批数量、最大候选数和超时必须大于 0。", file=sys.stderr)
        return 2
    if not shutil.which("openssl"):
        print("系统中没有找到 openssl，请先安装。", file=sys.stderr)
        return 2

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
        candidates = fetch_candidates(network, args.timeout)
    except (RuntimeError, ValueError, urllib.error.URLError, json.JSONDecodeError) as exc:
        print(f"域名发现失败：{exc}", file=sys.stderr)
        print("如果自动检测失败，请使用 --prefix 手动指定 VPS 前缀。", file=sys.stderr)
        return 1

    if not candidates:
        print("该前缀没有找到可用的证书域名。", file=sys.stderr)
        return 1

    candidates = candidates[: args.max_candidates]
    print(f"候选域名      ：{len(candidates)} 个（每批检测 {args.batch_size} 个）\n")

    h2_results: list[TestResult] = []
    core_results: list[TestResult] = []
    tested = 0
    for offset in range(0, len(candidates), args.batch_size):
        batch = candidates[offset : offset + args.batch_size]
        batch_number = offset // args.batch_size + 1
        print(f"--- 第 {batch_number} 批：{len(batch)} 个候选 ---")
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(batch)) as executor:
            futures = [
                executor.submit(
                    test_candidate,
                    candidate,
                    network,
                    args.timeout,
                    not args.allow_off_prefix,
                )
                for candidate in batch
            ]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                print_result(result)
                tested += 1
                if result.success:
                    core_results.append(result)
                    if result.h2:
                        h2_results.append(result)
        print()
        if len(h2_results) >= args.count:
            break

    selected = h2_results[: args.count]
    if len(selected) < args.count:
        selected_names = {result.hostname for result in selected}
        selected.extend(
            result
            for result in core_results
            if result.hostname not in selected_names
        )
        selected = selected[: args.count]

    print(f"已检测 {tested} 个候选，找到 {len(core_results)} 个核心条件合格的目标。")
    if not selected:
        print("没有找到兼容的目标域名。", file=sys.stderr)
        return 1

    output_path = Path(args.output).expanduser()
    write_output(output_path, selected, str(public_ip), str(network))
    print("\n推荐目标：")
    for index, result in enumerate(selected, 1):
        print(
            f"{index}. {result.hostname}:443  "
            f"H2={'是' if result.h2 else '否'}  {result.cipher}"
        )
    print(f"\n结果已保存到：{output_path.resolve()}")
    print("\n排名第一的技术候选配置：")
    print(f"  dest：{selected[0].hostname}:443")
    print(f"  serverNames：{selected[0].hostname}")
    print(f"  客户端 serverName：{selected[0].hostname}")
    print("\n注意：排名只依据 TLS 与网络检测，不代表域名信誉或内容质量。")
    return 0 if len(selected) >= args.count else 3


if __name__ == "__main__":
    raise SystemExit(main())
