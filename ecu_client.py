"""
Discover OPC UA servers on the network and subscribe to all variables found.

Discovery uses:
  1. Local Discovery Server (LDS) / FindServersOnNetwork
  2. FindServers on reachable hosts
  3. Subnet scan on common OPC UA ports (4840, 4841)

  python ecu_client.py
  python ecu_client.py --subnet 192.168.1.0/24

The Prüfwand controller only accepts a signed username login:

  python ecu_client.py --url opc.tcp://192.168.1.10:4840 --user admin --password <on the Steuerung>
"""
from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import os
import socket
import sys
import time
from datetime import datetime, timezone
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from asyncua import Client, ua
from asyncua.common.node import Node
from asyncua.crypto.cert_gen import setup_self_signed_certificate
from cryptography.x509.oid import ExtendedKeyUsageOID

DISCOVERY_PORTS = (4840, 4841)
PROBE_TIMEOUT = 1.5
SCAN_CONCURRENCY = 80
CONNECT_TIMEOUT = 10

LDS_URLS = (
    "opc.tcp://localhost:4840",
    "opc.tcp://127.0.0.1:4840",
)

DEFAULT_SUBNETS = (
    "192.168.1.0/24",
    "192.168.0.0/24",
    "10.0.0.0/24",
)

BROWSE_DEPTH = 8
MAX_VARIABLES_PER_SERVER = 2000
SUBSCRIPTION_MS = 500
CONFIG_PATH = Path(__file__).resolve().parent / "ecu.local.json"
RECORDINGS_DIR = Path(__file__).resolve().parent / "recordings"

# Tried in order. This controller publishes no "None" / anonymous endpoint.
SECURITY_ATTEMPTS = (
    "Basic256Sha256,SignAndEncrypt",
    "Basic256Sha256,Sign",
    "Aes128Sha256RsaOaep,SignAndEncrypt",
    "Aes256Sha256RsaPss,SignAndEncrypt",
    "Basic256,SignAndEncrypt",
)


@dataclass
class ServerConnection:
    label: str
    url: str
    client: Client
    subscription: object
    handler: DataHandler
    variables: list[Node] = field(default_factory=list)


# Structures such as SessionDiagnosticsDataType do not match this asyncua version
# and make the whole publish message fail to decode.
SIMPLE_VARIANT_TYPES = {
    ua.VariantType.Boolean,
    ua.VariantType.SByte,
    ua.VariantType.Byte,
    ua.VariantType.Int16,
    ua.VariantType.UInt16,
    ua.VariantType.Int32,
    ua.VariantType.UInt32,
    ua.VariantType.Int64,
    ua.VariantType.UInt64,
    ua.VariantType.Float,
    ua.VariantType.Double,
    ua.VariantType.String,
    ua.VariantType.DateTime,
    ua.VariantType.Guid,
    ua.VariantType.ByteString,
    ua.VariantType.LocalizedText,
    ua.VariantType.StatusCode,
}


class DataHandler:
    def __init__(self, server_label: str, record_file=None) -> None:
        self.server_label = server_label
        self.record_file = record_file
        self.count = 0

    def datachange_notification(self, node: Node, val, data) -> None:
        if self.record_file is None:
            print(f"[{self.server_label}] {node.nodeid.Identifier} = {val!r}")
        source_t = None
        status = None
        try:
            value = data.monitored_item.Value
            if value.SourceTimestamp is not None:
                source_t = value.SourceTimestamp.isoformat()
            if value.StatusCode is not None:
                status = value.StatusCode.name
        except Exception:
            pass
        if self.record_file is not None:
            row = {
                "t": datetime.now(timezone.utc).isoformat(),
                "source_t": source_t,
                "node_id": node.nodeid.to_string(),
                "name": str(node.nodeid.Identifier),
                "value": val,
                "status": status,
            }
            self.record_file.write(json.dumps(row, default=str) + "\n")
            self.count += 1


def local_ipv4_networks() -> set[ipaddress.IPv4Network]:
    networks: set[ipaddress.IPv4Network] = set()
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ip = ipaddress.IPv4Address(info[4][0])
            if ip.is_loopback or ip.is_link_local:
                continue
            networks.add(ipaddress.IPv4Network(f"{ip}/24", strict=False))
    except OSError:
        pass
    return networks


def normalize_endpoint_url(url: str) -> str:
    url = url.strip()
    if not url:
        return ""
    if not url.startswith("opc.tcp://"):
        url = f"opc.tcp://{url}"
    return url


def url_label(url: str) -> str:
    parsed = urlparse(url)
    host = parsed.hostname or url
    port = parsed.port or 4840
    return f"{host}:{port}"


def pin_hostname(hostname: str, ip: str) -> None:
    """Send traffic for an OPC UA hostname to a known IP without editing the hosts file."""
    original = socket.getaddrinfo

    def patched(host, port, *args, **kwargs):
        if host == hostname:
            host = ip
        return original(host, port, *args, **kwargs)

    socket.getaddrinfo = patched


async def prefer_reachable_url(url: str) -> str:
    """Use the server's advertised endpoint URL, pinned to the IP we can actually route to."""
    parsed = urlparse(url)
    ip = parsed.hostname or ""
    probe = Client(url, timeout=CONNECT_TIMEOUT)
    try:
        endpoints = await probe.connect_and_get_server_endpoints()
    except Exception as exc:
        print(f"[WARN] Could not read endpoints from {url}: {type(exc).__name__}: {exc}")
        return url

    for ep in endpoints or []:
        if not ep.EndpointUrl:
            continue
        advertised = normalize_endpoint_url(ep.EndpointUrl)
        host = urlparse(advertised).hostname
        if not host or host == ip:
            return advertised
        try:
            socket.getaddrinfo(host, urlparse(advertised).port or 4840)
        except socket.gaierror:
            pin_hostname(host, ip)
            print(f"[INFO] {host} does not resolve; sending it to {ip}")
        return advertised
    return url


async def ensure_client_certificate() -> tuple[Path, Path, str]:
    cert_dir = Path(__file__).resolve().parent / "certs"
    cert_dir.mkdir(exist_ok=True)
    key = cert_dir / "client_key.pem"
    cert = cert_dir / "client_cert.der"
    host = socket.gethostname()
    app_uri = f"urn:{host}:ecu-client"
    await setup_self_signed_certificate(
        key,
        cert,
        app_uri,
        host,
        [ExtendedKeyUsageOID.CLIENT_AUTH],
        {
            "countryName": "DE",
            "organizationName": "ecu-client",
        },
    )
    return cert, key, app_uri


async def simple_variables(nodes: list[Node]) -> list[Node]:
    kept: list[Node] = []
    for node in nodes:
        try:
            variant_type = await node.read_data_type_as_variant_type()
        except Exception:
            continue
        if variant_type in SIMPLE_VARIANT_TYPES:
            kept.append(node)
    return kept


async def collect_variables(node: Node, depth: int, found: list[Node]) -> None:
    if depth < 0 or len(found) >= MAX_VARIABLES_PER_SERVER:
        return

    try:
        node_class = await node.read_node_class()
    except Exception:
        return

    if node_class == ua.NodeClass.Variable:
        found.append(node)
        return

    try:
        children = await node.get_children()
    except Exception:
        return

    for child in children:
        await collect_variables(child, depth - 1, found)


async def probe_opc_host(ip: str, port: int, sem: asyncio.Semaphore) -> set[str]:
    async with sem:
        base = f"opc.tcp://{ip}:{port}/"
        client = Client(base, timeout=PROBE_TIMEOUT)
        try:
            endpoints = await client.connect_and_get_server_endpoints()
        except Exception:
            return set()

        urls: set[str] = set()
        if endpoints:
            for ep in endpoints:
                if ep.EndpointUrl:
                    urls.add(normalize_endpoint_url(ep.EndpointUrl))
        else:
            urls.add(base)
        return urls


async def scan_subnets(networks: Iterable[ipaddress.IPv4Network]) -> set[str]:
    hosts: list[tuple[str, int]] = []
    seen_ips: set[str] = set()

    for network in networks:
        for host in network.hosts():
            ip = str(host)
            if ip in seen_ips:
                continue
            seen_ips.add(ip)
            for port in DISCOVERY_PORTS:
                hosts.append((ip, port))

    print(f"[INFO] Scanning {len(hosts)} host/port combinations...")
    sem = asyncio.Semaphore(SCAN_CONCURRENCY)
    results = await asyncio.gather(*(probe_opc_host(ip, port, sem) for ip, port in hosts))

    urls: set[str] = set()
    for found in results:
        urls.update(found)
    return urls


async def discover_via_lds() -> set[str]:
    urls: set[str] = set()

    for lds_url in LDS_URLS:
        client = Client(lds_url, timeout=PROBE_TIMEOUT)
        try:
            print(f"[INFO] Querying discovery server {lds_url} ...")
            network_result = await client.connect_and_find_servers_on_network()
            servers = getattr(network_result, "Servers", None) or []
            for entry in servers:
                if entry.DiscoveryUrl:
                    urls.add(normalize_endpoint_url(entry.DiscoveryUrl))
                    print(f"  [LDS] {entry.ServerName}: {entry.DiscoveryUrl}")
        except Exception as exc:
            print(f"  [LDS] {lds_url} unavailable ({exc})")

        client2 = Client(lds_url, timeout=PROBE_TIMEOUT)
        try:
            for server in await client2.connect_and_find_servers():
                for discovery_url in server.DiscoveryUrls or []:
                    urls.add(normalize_endpoint_url(discovery_url))
                    name = server.ApplicationName.Text if server.ApplicationName else discovery_url
                    print(f"  [LDS] {name}: {discovery_url}")
        except Exception:
            pass

    return urls


async def discover_all(subnets: list[str]) -> list[str]:
    networks: set[ipaddress.IPv4Network] = set(local_ipv4_networks())

    for cidr in subnets:
        try:
            networks.add(ipaddress.IPv4Network(cidr, strict=False))
        except ValueError as exc:
            print(f"[WARN] Ignoring invalid subnet {cidr!r}: {exc}")

    for cidr in DEFAULT_SUBNETS:
        try:
            networks.add(ipaddress.IPv4Network(cidr, strict=False))
        except ValueError:
            pass

    print("[INFO] Starting OPC UA discovery...")
    discovered: set[str] = set()

    discovered.update(await discover_via_lds())
    discovered.update(await scan_subnets(networks))

    # Dedupe by host:port (different paths may point to the same server).
    by_host: dict[str, str] = {}
    for url in sorted(discovered):
        if not url:
            continue
        key = url_label(url)
        by_host.setdefault(key, url)

    urls = list(by_host.values())
    print(f"\n[INFO] Found {len(urls)} OPC UA server(s):")
    for url in urls:
        print(f"  - {url}")
    return urls


async def connect_server(
    url: str,
    username: str | None = None,
    password: str | None = None,
    record_file=None,
) -> ServerConnection | None:
    label = url_label(url)
    client = Client(url, timeout=CONNECT_TIMEOUT)

    if username and password:
        cert, key, app_uri = await ensure_client_certificate()
        last_error: Exception | None = None
        for security in SECURITY_ATTEMPTS:
            client = Client(url, timeout=CONNECT_TIMEOUT)
            client.application_uri = app_uri
            client.set_user(username)
            client.set_password(password)
            try:
                await client.set_security_string(f"{security},{cert},{key}")
                await client.connect()
                print(f"[INFO] {label}: connected as {username} ({security})")
                last_error = None
                break
            except Exception as exc:
                last_error = exc
                print(f"[WARN] {label}: {security} failed: {type(exc).__name__}: {exc}")
                try:
                    await client.disconnect()
                except Exception:
                    pass
        if last_error is not None:
            print(f"[WARN] Could not connect to {url}: {last_error}")
            return None
    else:
        try:
            await client.connect()
        except Exception as first_error:
            probe = Client(url, timeout=CONNECT_TIMEOUT)
            try:
                endpoints = await probe.connect_and_get_server_endpoints()
            except Exception:
                print(f"[WARN] Could not connect to {url}: {first_error}")
                return None
            finally:
                try:
                    await probe.disconnect()
                except Exception:
                    pass

            connected = False
            last_error = first_error
            for ep in endpoints or []:
                if not ep.EndpointUrl:
                    continue
                try_url = normalize_endpoint_url(ep.EndpointUrl)
                retry = Client(try_url, timeout=CONNECT_TIMEOUT)
                try:
                    await retry.connect()
                    client = retry
                    url = try_url
                    label = url_label(url)
                    connected = True
                    break
                except Exception as exc:
                    last_error = exc

            if not connected:
                print(f"[WARN] Could not connect to {url}: {last_error}")
                return None

    found: list[Node] = []
    await collect_variables(client.nodes.objects, BROWSE_DEPTH, found)
    variables = await simple_variables(found)

    if not variables:
        print(f"[WARN] {label}: connected but no simple variables under Objects")
        await client.disconnect()
        return None

    skipped = len(found) - len(variables)
    if skipped:
        print(f"[INFO] {label}: skipped {skipped} structure variable(s)")

    handler = DataHandler(label, record_file)
    # This server revises LifetimeCount to 3x MaxKeepAliveCount (16200).
    # Request that up front so asyncua does not warn and modify the subscription.
    params = ua.CreateSubscriptionParameters()
    params.RequestedPublishingInterval = SUBSCRIPTION_MS
    params.RequestedMaxKeepAliveCount = 5400
    params.RequestedLifetimeCount = 16200
    params.MaxNotificationsPerPublish = 100
    params.PublishingEnabled = True
    params.Priority = 0
    subscription = await client.create_subscription(params, handler)
    await subscription.subscribe_data_change(variables)

    print(f"[INFO] {label}: subscribed to {len(variables)} variable(s)")
    return ServerConnection(
        label=label,
        url=url,
        client=client,
        subscription=subscription,
        handler=handler,
        variables=variables,
    )


def new_recording_path() -> Path:
    RECORDINGS_DIR.mkdir(exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return RECORDINGS_DIR / f"session-{stamp}.jsonl"


async def run(
    subnets: list[str],
    url: str | None,
    username: str | None,
    password: str | None,
    minutes: float | None = None,
    output: str | None = None,
) -> None:
    if url:
        urls = [await prefer_reachable_url(normalize_endpoint_url(url))]
        print(f"[INFO] Connecting to {urls[0]}")
    else:
        urls = await discover_all(subnets)
    if not urls:
        print("[ERROR] No OPC UA servers found.")
        print("        Ensure devices are powered, on the same network, and OPC UA is enabled.")
        sys.exit(1)

    record_path = None
    record_file = None
    if minutes is not None:
        record_path = Path(output) if output else new_recording_path()
        record_path.parent.mkdir(parents=True, exist_ok=True)
        record_file = record_path.open("w", encoding="utf-8", buffering=1)
        record_file.write(
            json.dumps(
                {
                    "type": "session",
                    "started": datetime.now(timezone.utc).isoformat(),
                    "minutes": minutes,
                    "url": urls[0] if len(urls) == 1 else urls,
                }
            )
            + "\n"
        )
        print(f"[INFO] Recording {minutes:g} min to {record_path}")

    connections: list[ServerConnection] = []
    try:
        for found in urls:
            conn = await connect_server(found, username, password, record_file)
            if conn is not None:
                connections.append(conn)

        if not connections:
            print("[ERROR] Found servers during discovery but could not subscribe to any.")
            sys.exit(1)

        total_vars = sum(len(c.variables) for c in connections)
        print(f"\n[INFO] Listening on {len(connections)} server(s), {total_vars} variable(s) total.")
        if minutes is None:
            print("[INFO] Press Ctrl+C to stop.\n")
        else:
            print(f"[INFO] Recording for {minutes:g} min. Press Ctrl+C to stop early.\n")

        started = time.monotonic()
        next_report = started + 30
        try:
            while True:
                now = time.monotonic()
                if minutes is not None and now - started >= minutes * 60:
                    break
                if minutes is not None and now >= next_report:
                    samples = sum(conn.handler.count for conn in connections)
                    print(f"[INFO] {int(now - started)}s elapsed, {samples} samples")
                    next_report += 30
                await asyncio.sleep(1)
        finally:
            for conn in connections:
                try:
                    await conn.client.disconnect()
                except Exception:
                    pass
            print("[INFO] Disconnected from all servers.")
    finally:
        if record_file is not None and record_path is not None:
            samples = sum(conn.handler.count for conn in connections)
            record_file.write(
                json.dumps(
                    {
                        "type": "session_end",
                        "ended": datetime.now(timezone.utc).isoformat(),
                        "samples": samples,
                    }
                )
                + "\n"
            )
            record_file.close()
            print(f"[INFO] Recording saved: {record_path} ({samples} samples)")


def load_config() -> dict:
    if not CONFIG_PATH.is_file():
        return {}
    try:
        data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[WARN] Could not read {CONFIG_PATH.name}: {exc}")
        return {}
    return data if isinstance(data, dict) else {}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Discover OPC UA servers and subscribe to all variables."
    )
    parser.add_argument(
        "--subnet",
        action="append",
        default=[],
        metavar="CIDR",
        help="Extra subnet to scan (e.g. 192.168.1.0/24). Can be repeated.",
    )
    parser.add_argument(
        "--url",
        default=None,
        help="Connect to this OPC UA endpoint instead of scanning. Example: opc.tcp://192.168.1.10:4840",
    )
    parser.add_argument(
        "--scan",
        action="store_true",
        help="Scan the network instead of using the saved endpoint in ecu.local.json.",
    )
    parser.add_argument("--user", default=os.environ.get("OPCUA_USER", "admin"), help="OPC UA username")
    parser.add_argument(
        "--password",
        default=os.environ.get("OPCUA_PASSWORD"),
        help="OPC UA password. Defaults to the OPCUA_PASSWORD environment variable.",
    )
    parser.add_argument(
        "--minutes",
        type=float,
        default=None,
        metavar="N",
        help="Record this many minutes, then disconnect and save the file.",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Recording file. Default is recordings/session-YYYYMMDD-HHMMSS.jsonl.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    config = load_config()
    if args.scan:
        args.url = None
    elif not args.url:
        args.url = config.get("url")
    if args.user == "admin" and config.get("username"):
        args.user = config["username"]
    if not args.password:
        args.password = config.get("password") or os.environ.get("OPCUA_PASSWORD")
    if args.url and not args.password:
        print("[ERROR] This server requires a username and password.")
        print(f"        Put them in {CONFIG_PATH.name}, or pass --user and --password.")
        sys.exit(1)
    try:
        asyncio.run(
            run(
                args.subnet,
                args.url,
                args.user if args.password else None,
                args.password,
                args.minutes,
                args.output,
            )
        )
    except KeyboardInterrupt:
        print("\n[INFO] Stopped by user.")


if __name__ == "__main__":
    main()
