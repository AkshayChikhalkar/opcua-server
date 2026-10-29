"""Record B&R X90 logbooks from the System Diagnostics Manager.

The CPU that answers on this network is 192.168.1.12. Its OPC UA server is
not running, so process variables cannot be subscribed yet. The diagnostics
page already publishes the logbooks over HTTP, and this recorder stores the
new lines in the same Timescale database as the other controllers.

  python br_recorder.py
  python br_recorder.py --once
"""

from __future__ import annotations

import argparse
import json
import os
import time
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path
from urllib.parse import quote

import psycopg

ROOT = Path(__file__).resolve().parent
CONFIG_PATH = ROOT / "br.local.json"
DEFAULT_HOST = "192.168.1.12"
CONTROLLER_NAME = "B&R X90"

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
    parser = argparse.ArgumentParser(description="Record B&R X90 logbooks.")
    parser.add_argument("--once", action="store_true", help="Read the logbooks once and exit.")
    args = parser.parse_args()
    config = load_config()
    host = str(config.get("host") or DEFAULT_HOST).strip()
    interval = float(config.get("interval_seconds") or 15)
    store = Store.connect()
    print("Recording B&R logbooks from http://%s/sdm every %.0fs." % (host, interval))
    try:
        if args.once:
            print("Stored %s new log line(s)." % poll_once(host, store))
            return
        while True:
            try:
                count = poll_once(host, store)
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                print("B&R diagnostics did not answer: %s" % exc)
                count = 0
            if count == 0:
                print("No new log lines.")
            time.sleep(interval)
    except KeyboardInterrupt:
        print("Stopped.")
    finally:
        store.mark_offline()
        store.close()


if __name__ == "__main__":
    main()
