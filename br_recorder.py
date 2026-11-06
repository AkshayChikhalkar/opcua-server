"""Record a B&R X90: diagnostic logbooks and every published PLC variable.

The CPU on this network is 192.168.1.12. Logbooks come from the System
Diagnostics Manager over HTTP. Live values come from its OPC UA server.
The project decides which variables that server publishes; this recorder
subscribes to all of them and stores new values in Timescale.

  python br_recorder.py
  python br_recorder.py --once
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

import psycopg
from asyncua import Client, ua
from asyncua.common.node import Node

ROOT = Path(__file__).resolve().parent
CONFIG_PATH = ROOT / "br.local.json"
DEFAULT_HOST = "192.168.1.12"
CONTROLLER_NAME = "B&R X90"
OPC_PORT = 4840
# OPC UA built-in scalar data types. Structures are skipped.
SCALAR_TYPES = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 19, 21}
PLC_ROOTS = ("ns=4;i=20000", "ns=4;i=21001")

BOOK_NAMES = {
    "$accsec": "Access log",
    "$arlogconn": "Connection log",
    "$arlogsys": "System log",
    "$arlogusr": "User log",
    "$fieldbus": "Fieldbus log",
    "$firewall": "Firewall log",
    "$motion": "Motion log",
    "$safety": "Safety log",
    "$textsys": "Text system log",
    "$unitsys": "Unit system log",
    "$versinfo": "Version log",
}


def load_env_file() -> None:
    path = ROOT / ".env"
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def load_config() -> dict:
    config = {"host": DEFAULT_HOST, "interval_seconds": 15}
    if not CONFIG_PATH.is_file():
        return config
    loaded = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    if isinstance(loaded, dict):
        config.update(loaded)
    return config


def fetch(url: str) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": "opcua-recorder"})
    with urllib.request.urlopen(request, timeout=8) as response:
        return response.read().decode("utf-8", "replace")


def js_arrays(text: str, function_name: str) -> list[list[str]]:
    """Read new Array('a','b',...) rows from one generated JavaScript function."""
    marker = "function %s()" % function_name
    start = text.find(marker)
    if start < 0:
        return []
    body = text[start:]
    rows: list[list[str]] = []
    token = "new Array("
    index = 0
    while True:
        found = body.find(token, index)
        if found < 0:
            break
        cursor = found + len(token)
        parts: list[str] = []
        while cursor < len(body) and body[cursor] != ")":
            if body[cursor] in " \t\r\n,":
                cursor += 1
                continue
            if body[cursor] != "'":
                break
            cursor += 1
            chars: list[str] = []
            while cursor < len(body):
                char = body[cursor]
                if char == "\\" and cursor + 1 < len(body):
                    chars.append(body[cursor + 1])
                    cursor += 2
                    continue
                if char == "'":
                    cursor += 1
                    break
                chars.append(char)
                cursor += 1
            parts.append("".join(chars))
        if parts:
            rows.append(parts)
        index = cursor
    return rows


def plc_time(text: str) -> datetime:
    stamp = datetime.strptime(text.strip(), "%Y-%m-%d / %H:%M:%S.%f")
    return stamp.replace(tzinfo=datetime.now().astimezone().tzinfo)


def message_text(parts: list[str]) -> str:
    object_name = parts[3].strip() if len(parts) > 3 else ""
    detail = parts[4].strip() if len(parts) > 4 else ""
    message = parts[5].strip() if len(parts) > 5 else ""
    return " | ".join(piece for piece in (object_name, detail, message) if piece)


def logger_url(host: str, module: str | None) -> str:
    url = "http://%s/sdm/svg.cgi?type=logger" % host
    if module:
        url += "&module=" + quote(module, safe="$")
    return url


class Store:
    def __init__(self, connection: psycopg.Connection) -> None:
        self.connection = connection
        self.controller_id: int | None = None
        self.signals: dict[str, int] = {}
        self.seen: set[tuple] = set()

    @classmethod
    def connect(cls) -> "Store":
        load_env_file()
        connection = psycopg.connect(
            host=os.environ.get("POSTGRES_HOST", "127.0.0.1"),
            port=int(os.environ.get("POSTGRES_PORT", "5432")),
            user=os.environ.get("POSTGRES_USER", "recorder"),
            password=os.environ["POSTGRES_PASSWORD"],
            dbname=os.environ.get("POSTGRES_DB", "recorder"),
            autocommit=True,
        )
        return cls(connection)

    def close(self) -> None:
        self.connection.close()

    def controller(self, endpoint: str) -> int:
        if self.controller_id is not None:
            return self.controller_id
        with self.connection.cursor() as cur:
            cur.execute(
                """
                INSERT INTO controllers (name, endpoint)
                VALUES (%s, %s)
                ON CONFLICT (endpoint) DO UPDATE SET name = EXCLUDED.name
                RETURNING id
                """,
                (CONTROLLER_NAME, endpoint),
            )
            self.controller_id = cur.fetchone()[0]
            cur.execute(
                """
                SELECT s.identifier, sa.time, sa.status, sa.value_text
                FROM samples sa
                JOIN signals s ON s.id = sa.signal_id
                WHERE s.controller_id = %s
                  AND sa.received_at > now() - interval '14 days'
                """,
                (self.controller_id,),
            )
            for identifier, when, status, text in cur.fetchall():
                self.seen.add((identifier, when, status or "", text or ""))
        return self.controller_id

    def signal(self, controller_id: int, book: str) -> int:
        cached = self.signals.get(book)
        if cached is not None:
            return cached
        identifier = book[1:] if book.startswith("$") else book
        name = BOOK_NAMES.get(book, identifier)
        with self.connection.cursor() as cur:
            cur.execute(
                """
                INSERT INTO signals (controller_id, namespace, identifier, name)
                VALUES (%s, 0, %s, %s)
                ON CONFLICT (controller_id, namespace, identifier)
                DO UPDATE SET name = EXCLUDED.name
                RETURNING id
                """,
                (controller_id, identifier, name),
            )
            signal_id = cur.fetchone()[0]
        self.signals[book] = signal_id
        return signal_id

    def write(self, endpoint: str, book: str, when: datetime, level: float, code: str, text: str) -> bool:
        controller_id = self.controller(endpoint)
        identifier = book[1:] if book.startswith("$") else book
        key = (identifier, when, code, text)
        if key in self.seen:
            return False
        signal_id = self.signal(controller_id, book)
        with self.connection.cursor() as cur:
            cur.execute(
                """
                INSERT INTO samples (time, received_at, signal_id, value_num, value_text, status)
                VALUES (%s, now(), %s, %s, %s, %s)
                """,
                (when, signal_id, level, text, code),
            )
            cur.execute(
                """
                INSERT INTO latest (signal_id, time, value_num, value_text, status)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (signal_id) DO UPDATE SET
                    time = EXCLUDED.time,
                    value_num = EXCLUDED.value_num,
                    value_text = EXCLUDED.value_text,
                    status = EXCLUDED.status
                WHERE latest.time <= EXCLUDED.time
                """,
                (signal_id, when, level, text, code),
            )
            cur.execute(
                """
                INSERT INTO recorder_status (controller_id, last_seen, listening)
                VALUES (%s, now(), true)
                ON CONFLICT (controller_id) DO UPDATE
                SET last_seen = now(), listening = true
                """,
                (controller_id,),
            )
        self.seen.add(key)
        return True

    def touch(self) -> None:
        if self.controller_id is None:
            return
        with self.connection.cursor() as cur:
            cur.execute(
                """
                INSERT INTO recorder_status (controller_id, last_seen, listening)
                VALUES (%s, now(), true)
                ON CONFLICT (controller_id) DO UPDATE
                SET last_seen = now(), listening = true
                """,
                (self.controller_id,),
            )

    def mark_offline(self) -> None:
        if self.controller_id is None:
            return
        with self.connection.cursor() as cur:
            cur.execute(
                """
                UPDATE recorder_status
                SET listening = false, last_seen = now()
                WHERE controller_id = %s
                """,
                (self.controller_id,),
            )


def split_sample_value(value) -> tuple[float | None, str | None]:
    if value is None:
        return None, None
    if isinstance(value, bool):
        return float(value), None
    if isinstance(value, (int, float)):
        return float(value), None
    text = getattr(value, "Text", None)
    if isinstance(text, str):
        return None, text or None
    if isinstance(value, str):
        return None, value or None
    return None, str(value)


class ValueStore:
    """Writes OPC UA values for the same CPU, on their own database connection."""

    def __init__(self, connection: psycopg.Connection, endpoint: str) -> None:
        self.connection = connection
        self.endpoint = endpoint
        self.controller_id: int | None = None
        self.signals: dict[str, int] = {}
        self.last: dict[str, tuple] = {}
        self.lock = threading.Lock()

    @classmethod
    def connect(cls, endpoint: str) -> "ValueStore":
        load_env_file()
        connection = psycopg.connect(
            host=os.environ.get("POSTGRES_HOST", "127.0.0.1"),
            port=int(os.environ.get("POSTGRES_PORT", "5432")),
            user=os.environ.get("POSTGRES_USER", "recorder"),
            password=os.environ["POSTGRES_PASSWORD"],
            dbname=os.environ.get("POSTGRES_DB", "recorder"),
            autocommit=True,
        )
        return cls(connection, endpoint)

    def close(self) -> None:
        self.connection.close()

    def register(self, variables: list[tuple[Node, str]]) -> None:
        with self.lock:
            with self.connection.cursor() as cur:
                if self.controller_id is None:
                    cur.execute(
                        """
                        INSERT INTO controllers (name, endpoint)
                        VALUES (%s, %s)
                        ON CONFLICT (endpoint) DO UPDATE SET name = EXCLUDED.name
                        RETURNING id
                        """,
                        (CONTROLLER_NAME, self.endpoint),
                    )
                    self.controller_id = cur.fetchone()[0]
                for node, name in variables:
                    key = node.nodeid.to_string()
                    if key in self.signals:
                        continue
                    cur.execute(
                        """
                        INSERT INTO signals (controller_id, namespace, identifier, name)
                        VALUES (%s, %s, %s, %s)
                        ON CONFLICT (controller_id, namespace, identifier)
                        DO UPDATE SET name = EXCLUDED.name
                        RETURNING id
                        """,
                        (self.controller_id, node.nodeid.NamespaceIndex, str(node.nodeid.Identifier), name),
                    )
                    self.signals[key] = cur.fetchone()[0]

    def write(self, node_id: str, when, value, status: str | None) -> None:
        signal_id = self.signals.get(node_id)
        if signal_id is None:
            return
        value_num, value_text = split_sample_value(value)
        if value_num is None and not value_text:
            return
        current = (value_num, value_text)
        if self.last.get(node_id) == current:
            return
        if when is None:
            when = datetime.now(timezone.utc)
        with self.lock:
            with self.connection.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO samples (time, received_at, signal_id, value_num, value_text, status)
                    VALUES (%s, now(), %s, %s, %s, %s)
                    """,
                    (when, signal_id, value_num, value_text, status),
                )
                cur.execute(
                    """
                    INSERT INTO latest (signal_id, time, value_num, value_text, status)
                    VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (signal_id) DO UPDATE SET
                        time = EXCLUDED.time,
                        value_num = EXCLUDED.value_num,
                        value_text = EXCLUDED.value_text,
                        status = EXCLUDED.status
                    WHERE latest.time <= EXCLUDED.time
                    """,
                    (signal_id, when, value_num, value_text, status),
                )
                cur.execute(
                    """
                    INSERT INTO recorder_status (controller_id, last_seen, listening)
                    VALUES (%s, now(), true)
                    ON CONFLICT (controller_id) DO UPDATE
                    SET last_seen = now(), listening = true
                    """,
                    (self.controller_id,),
                )
        self.last[node_id] = current

    def touch(self) -> None:
        if self.controller_id is None:
            return
        with self.lock:
            with self.connection.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO recorder_status (controller_id, last_seen, listening)
                    VALUES (%s, now(), true)
                    ON CONFLICT (controller_id) DO UPDATE
                    SET last_seen = now(), listening = true
                    """,
                    (self.controller_id,),
                )

    def mark_offline(self) -> None:
        if self.controller_id is None:
            return
        with self.lock:
            with self.connection.cursor() as cur:
                cur.execute(
                    """
                    UPDATE recorder_status
                    SET listening = false, last_seen = now()
                    WHERE controller_id = %s
                    """,
                    (self.controller_id,),
                )


class ValueHandler:
    def __init__(self, store: ValueStore) -> None:
        self.store = store

    def datachange_notification(self, node: Node, val, data) -> None:
        when = None
        status = None
        try:
            value = data.monitored_item.Value
            when = value.SourceTimestamp
            if value.StatusCode is not None:
                status = value.StatusCode.name
        except Exception:
            pass
        try:
            self.store.write(node.nodeid.to_string(), when, val, status)
        except Exception as exc:
            print("OPC UA write failed: %s" % exc)

    def status_change_notification(self, status) -> None:
        return None


async def plc_variables(client: Client) -> list[tuple[Node, str]]:
    """Every scalar the PLC actually publishes, from both address-space views."""
    found: list[tuple[Node, str]] = []
    seen: set[str] = set()

    async def walk(node: Node, prefix: str, depth: int) -> None:
        if depth > 8:
            return
        try:
            children = await node.get_children()
        except Exception:
            return
        for child in children:
            key = child.nodeid.to_string()
            if key in seen:
                continue
            seen.add(key)
            try:
                browse_name = (await child.read_browse_name()).Name
                node_class = await child.read_node_class()
            except Exception:
                continue
            label = "%s/%s" % (prefix, browse_name) if prefix else browse_name
            if node_class == ua.NodeClass.Variable:
                try:
                    data_type = await child.read_data_type()
                except Exception:
                    continue
                identifier = data_type.Identifier
                if data_type.NamespaceIndex == 0 and isinstance(identifier, int) and identifier in SCALAR_TYPES:
                    found.append((child, label))
            elif node_class == ua.NodeClass.Object:
                await walk(child, label, depth + 1)

    for root_id in PLC_ROOTS:
        root = client.get_node(root_id)
        await walk(root, "", 0)
    return found


async def watch_values(host: str, stop: threading.Event) -> None:
    endpoint = "opc.tcp://%s:%d" % (host, OPC_PORT)
    try:
        store = ValueStore.connect(endpoint)
    except Exception as exc:
        print("OPC UA database did not answer: %s" % exc)
        return
    try:
        while not stop.is_set():
            client = Client(endpoint, timeout=10)
            subscription = None
            subscribed: set[str] = set()
            try:
                await client.connect()
                print("OPC UA %s: connected." % endpoint)
                while not stop.is_set():
                    variables = await plc_variables(client)
                    keys = {node.nodeid.to_string() for node, _name in variables}
                    if keys != subscribed:
                        if subscription is not None:
                            await subscription.delete()
                            subscription = None
                        store.register(variables)
                        if variables:
                            params = ua.CreateSubscriptionParameters()
                            params.RequestedPublishingInterval = 1000
                            params.RequestedMaxKeepAliveCount = 1200
                            params.RequestedLifetimeCount = 3600
                            params.MaxNotificationsPerPublish = 100
                            params.PublishingEnabled = True
                            params.Priority = 0
                            subscription = await client.create_subscription(params, ValueHandler(store))
                            await subscription.subscribe_data_change(
                                [node for node, _name in variables],
                                sampling_interval=1000,
                            )
                        print(
                            "OPC UA %s: recording %d variable(s): %s"
                            % (endpoint, len(variables), ", ".join(name for _node, name in variables))
                        )
                        subscribed = keys
                    store.touch()
                    for _ in range(30):
                        if stop.is_set():
                            break
                        await asyncio.sleep(1)
            except Exception as exc:
                print("OPC UA did not answer: %s" % exc)
                for _ in range(15):
                    if stop.is_set():
                        break
                    await asyncio.sleep(1)
            finally:
                try:
                    await client.disconnect()
                except Exception:
                    pass
    finally:
        store.mark_offline()
        store.close()


def books_in(text: str) -> list[str]:
    names = []
    for parts in js_arrays(text, "getIT1"):
        if parts and parts[0].startswith("$"):
            names.append(parts[0])
    return names


def poll_once(host: str, store: Store) -> int:
    endpoint = "sdm://%s" % host
    catalog = fetch(logger_url(host, None))
    books = books_in(catalog) or list(BOOK_NAMES)
    written = 0
    for book in books:
        try:
            page = fetch(logger_url(host, book))
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            print("%s: %s" % (book, exc))
            continue
        added = 0
        newest = None
        for parts in js_arrays(page, "getIT"):
            if len(parts) < 3:
                continue
            try:
                when = plc_time(parts[1])
                level = float(parts[0])
            except ValueError:
                continue
            text = message_text(parts)
            if newest is None:
                newest = "%s  %s" % (parts[1], text)
            if store.write(endpoint, book, when, level, parts[2], text):
                added += 1
        if added and newest:
            print("%s  %s new, latest: %s" % (book, added, newest))
        written += added
    return written


def main() -> None:
    parser = argparse.ArgumentParser(description="Record B&R X90 logbooks and OPC UA values.")
    parser.add_argument("--once", action="store_true", help="Read the logbooks once and exit.")
    args = parser.parse_args()
    config = load_config()
    host = str(config.get("host") or DEFAULT_HOST).strip()
    interval = float(config.get("interval_seconds") or 15)
    store = Store.connect()
    stop = threading.Event()
    opc = threading.Thread(target=lambda: asyncio.run(watch_values(host, stop)), name="br-opc", daemon=True)
    if not args.once:
        opc.start()
    print("Recording B&R logbooks from http://%s/sdm every %.0fs." % (host, interval))
    if not args.once:
        print("Recording B&R values from opc.tcp://%s:%d." % (host, OPC_PORT))
    try:
        if args.once:
            print("Stored %s new log line(s)." % poll_once(host, store))
            return
        while True:
            try:
                count = poll_once(host, store)
                store.touch()
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                print("B&R diagnostics did not answer: %s" % exc)
                count = 0
            if count == 0:
                print("No new log lines.")
            time.sleep(interval)
    except KeyboardInterrupt:
        print("Stopped.")
    finally:
        stop.set()
        if opc.is_alive():
            opc.join(timeout=12)
        store.mark_offline()
        store.close()


if __name__ == "__main__":
    main()
