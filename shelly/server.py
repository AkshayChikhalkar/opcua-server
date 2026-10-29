"""Local dashboard for devices on the network.

A device can be a Shelly relay, another HTTP switch, or a controller with
its own switches. The browser talks only to this server. Shelly devices do
not send CORS headers, so the server calls them over HTTP.
"""

from __future__ import annotations

import copy
import ipaddress
import json
import re
import socket
import threading
import urllib.error
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

HOST = "127.0.0.1"
PORT = 8765
ROOT = Path(__file__).resolve().parent
INDEX = ROOT / "index.html"
STORE = ROOT / "devices.json"
LOCK = threading.Lock()
HOST_PATTERN = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
)
ID_PATTERN = re.compile(r"^[a-f0-9]{32}$")
PATH_PATTERN = re.compile(r"^/[A-Za-z0-9._~!$&'()*+,;=:@%/?-]{0,200}$")
KEY_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,40}(?:\.[A-Za-z0-9_-]{1,40}){0,5}$")
DEVICE_CMD = re.compile(r"^/api/devices/([a-f0-9]{32})/(on|off)$")
DEVICE_ITEM = re.compile(r"^/api/devices/([a-f0-9]{32})$")
CONTROL_ADD = re.compile(r"^/api/devices/([a-f0-9]{32})/controls$")
CONTROL_CMD = re.compile(r"^/api/devices/([a-f0-9]{32})/controls/([a-f0-9]{32})/(on|off)$")
CONTROL_ITEM = re.compile(r"^/api/devices/([a-f0-9]{32})/controls/([a-f0-9]{32})$")

SEED = [
    {
        "id": "a1b2c3d4e5f64789a0b1c2d3e4f50617",
        "name": "Lynx Smart BMS HQ252",
        "host": "192.168.140.36",
        "kind": "shelly-gen2",
        "switch_id": 0,
    }
]


class DeviceError(Exception):
    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = status


def parse_host(raw: str) -> str:
    value = raw.strip()
    if value.endswith("."):
        value = value[:-1]
    if not value or not HOST_PATTERN.fullmatch(value):
        raise DeviceError("Enter a local address, such as 192.168.140.36")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        if not value.lower().endswith(".local"):
            raise DeviceError("Enter a local address, such as 192.168.140.36")
        return value.lower()
    if address.version != 4 or not (address.is_private or address.is_link_local):
        raise DeviceError("Enter an address on your local network")
    if address.is_loopback or address.is_multicast or address.is_unspecified:
        raise DeviceError("Enter the device's own address")
    return str(address)


def parse_shelly_host(raw: str) -> str:
    value = raw.strip()
    value = re.sub(r"^https?://", "", value, flags=re.IGNORECASE)
    value = value.split("/", 1)[0].split("?", 1)[0].strip()
    if ":" in value:
        raise DeviceError("Enter the address without a port")
    return parse_host(value)


def split_host_port(value: str, default_port: int) -> tuple[str, int]:
    value = value.strip().strip("/")
    if value.count(":") > 1:
        raise DeviceError("Enter an IPv4 address")
    if ":" in value:
        host_text, port_text = value.rsplit(":", 1)
        if not port_text.isdigit():
            raise DeviceError("Enter a valid port")
        port = int(port_text)
    else:
        host_text, port = value, default_port
    if port < 1 or port > 65535:
        raise DeviceError("Enter a valid port")
    return parse_host(host_text), port


def parse_endpoint(raw: str) -> dict:
    value = raw.strip()
    lowered = value.lower()
    if lowered.startswith("opc.tcp://"):
        host, port = split_host_port(value[len("opc.tcp://"):].split("/", 1)[0], 4840)
        endpoint = "opc.tcp://%s:%d" % (host, port)
    elif lowered.startswith("http://"):
        host, port = split_host_port(value[len("http://"):].split("/", 1)[0], 80)
        endpoint = "http://%s:%d" % (host, port)
    else:
        host, port = split_host_port(value.split("/", 1)[0], 80)
        endpoint = host if port == 80 else "%s:%d" % (host, port)
    return {"host": host, "port": port, "endpoint": endpoint}


def parse_path(raw: str, label: str) -> str:
    value = raw.strip()
    if not PATH_PATTERN.fullmatch(value) or ".." in value.split("?", 1)[0].split("/"):
        raise DeviceError("Enter a %s path that starts with /" % label)
    return value


def parse_status_key(raw: str) -> str:
    value = raw.strip() or "output"
    if not KEY_PATTERN.fullmatch(value):
        raise DeviceError("Enter a status field such as output")
    return value


def clean_name(raw: str, fallback: str = "") -> str:
    value = raw.strip()[:60]
    if not value:
        if not fallback:
            raise DeviceError("Enter a name")
        return fallback[:60]
    return value


def http_call(host: str, path: str, timeout: float) -> tuple[int, bytes]:
    request = urllib.request.Request(
        "http://%s%s" % (host, path),
        headers={"Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        error.read()
        if error.code == 401:
            raise DeviceError("The device refused the request", 401)
        if error.code == 404:
            raise DeviceError("The device has no page at that path", 404)
        raise DeviceError("The device refused the request", error.code)
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise DeviceError("Nothing answered at that address", 502) from error


def http_json(host: str, path: str, timeout: float) -> dict:
    _status, body = http_call(host, path, timeout)
    if not body.strip():
        raise DeviceError("The device returned no status")
    try:
        data = json.loads(body.decode())
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DeviceError("The device did not return status JSON") from error
    if not isinstance(data, dict):
        raise DeviceError("The device did not return status JSON")
    return data


def lookup_key(data: dict, key: str):
    current = data
    for part in key.split("."):
        if not isinstance(current, dict) or part not in current:
            raise DeviceError("The status did not include %s" % key)
        current = current[part]
    return current


def as_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and value in (0, 1):
        return bool(value)
    if isinstance(value, str) and value.lower() in ("true", "false", "on", "off", "1", "0"):
        return value.lower() in ("true", "on", "1")
    raise DeviceError("The status value is not on or off")


def pretty_app(app: object) -> str:
    if not isinstance(app, str) or not app.strip():
        return "Shelly"
    match = re.fullmatch(r"Pro(\d+)", app.strip())
    if match:
        return "Shelly Pro " + match.group(1)
    return "Shelly " + app.strip()


def choose_name(requested: str, info: dict, config: dict, switch_id: int, count: int) -> str:
    configured = config.get("name")
    configured = configured.strip() if isinstance(configured, str) else ""
    device_name = info.get("name")
    device_name = device_name.strip() if isinstance(device_name, str) else ""
    if requested:
        label = requested
    elif configured:
        label = configured
    else:
        label = device_name or pretty_app(info.get("app"))
    if count > 1 and (requested or not configured):
        label = "%s %d" % (label, switch_id + 1)
    return label[:60]


def discover(host: str, requested_name: str) -> list[dict]:
    try:
        info = http_json(host, "/rpc/Shelly.GetDeviceInfo", 5)
    except DeviceError as error:
        if error.status == 401:
            raise DeviceError("That Shelly has authentication turned on")
        if error.status == 404:
            return discover_gen1(host, requested_name)
        raise
    if "gen" not in info:
        return discover_gen1(host, requested_name)
    status = http_json(host, "/rpc/Shelly.GetStatus", 5)
    switch_ids = sorted(
        int(key.split(":", 1)[1])
        for key in status
        if key.startswith("switch:") and key.split(":", 1)[1].isdigit()
    )
    if not switch_ids:
        raise DeviceError("That device has no relay to switch")
    found = []
    for switch_id in switch_ids:
        try:
            config = http_json(host, "/rpc/Switch.GetConfig?id=%d" % switch_id, 5)
        except DeviceError:
            config = {}
        found.append(
            {
                "name": choose_name(requested_name, info, config, switch_id, len(switch_ids)),
                "host": host,
                "kind": "shelly-gen2",
                "switch_id": switch_id,
            }
        )
    return found


def discover_gen1(host: str, requested_name: str) -> list[dict]:
    try:
        info = http_json(host, "/shelly", 5)
    except DeviceError as error:
        if error.status == 401:
            raise DeviceError("That Shelly has authentication turned on")
        raise
    if info.get("gen", 1) not in (1, "1"):
        raise DeviceError("That address is not a Shelly relay")
    status = http_json(host, "/status", 5)
    relays = status.get("relays")
    if not isinstance(relays, list) or not relays:
        raise DeviceError("That device has no relay to switch")
    label = requested_name or pretty_app(info.get("type"))
    return [
        {
            "name": (label if len(relays) == 1 else "%s %d" % (label, switch_id + 1))[:60],
            "host": host,
            "kind": "shelly-gen1",
            "switch_id": switch_id,
        }
        for switch_id in range(len(relays))
    ]


def normalize_switch(item: dict, require_id: bool) -> dict:
    kind = item.get("kind")
    name = item.get("name")
    host = item.get("host")
    switch_id = item.get("switch_id", 0)
    if not isinstance(name, str) or not name.strip() or not isinstance(host, str):
        raise DeviceError("The saved device list is unreadable", 500)
    if kind in ("shelly-gen1", "shelly-gen2"):
        if not isinstance(switch_id, int) or switch_id < 0:
            raise DeviceError("The saved device list is unreadable", 500)
        record = {
            "name": name.strip()[:60],
            "host": host,
            "kind": kind,
            "switch_id": switch_id,
        }
    elif kind == "http-switch":
        record = {
            "name": name.strip()[:60],
            "host": host,
            "kind": kind,
            "on_path": item.get("on_path"),
            "off_path": item.get("off_path"),
            "status_path": item.get("status_path"),
            "status_key": item.get("status_key"),
        }
        if not all(isinstance(record[key], str) and record[key] for key in ("on_path", "off_path", "status_path", "status_key")):
            raise DeviceError("The saved device list is unreadable", 500)
    else:
        raise DeviceError("The saved device list is unreadable", 500)
    if require_id:
        device_id = item.get("id")
        if not isinstance(device_id, str) or not ID_PATTERN.fullmatch(device_id):
            raise DeviceError("The saved device list is unreadable", 500)
        record["id"] = device_id
    return record


def normalize(item: object) -> dict:
    if not isinstance(item, dict):
        raise DeviceError("The saved device list is unreadable", 500)
    kind = item.get("kind")
    if kind == "controller":
        device_id = item.get("id")
        name = item.get("name")
        host = item.get("host")
        endpoint = item.get("endpoint")
        port = item.get("port")
        controls = item.get("controls", [])
        if (
            not isinstance(device_id, str)
            or not ID_PATTERN.fullmatch(device_id)
            or not isinstance(name, str)
            or not name.strip()
            or not isinstance(host, str)
            or not isinstance(endpoint, str)
            or not isinstance(port, int)
            or not isinstance(controls, list)
        ):
            raise DeviceError("The saved device list is unreadable", 500)
        return {
            "id": device_id,
            "name": name.strip()[:60],
            "host": host,
            "endpoint": endpoint,
            "port": port,
            "kind": "controller",
            "controls": [normalize_switch(control, True) for control in controls],
        }
    record = normalize_switch(item, True)
    return record


def load_unlocked() -> list[dict]:
    if not STORE.exists():
        saved = copy.deepcopy(SEED)
        write_unlocked(saved)
        return saved
    try:
        data = json.loads(STORE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise DeviceError("The saved device list is unreadable", 500) from error
    if not isinstance(data, list):
        raise DeviceError("The saved device list is unreadable", 500)
    return [normalize(item) for item in data]


def read_devices() -> list[dict]:
    with LOCK:
        return load_unlocked()


def write_unlocked(devices: list[dict]) -> None:
    temporary = STORE.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(devices, indent=2) + "\n", encoding="utf-8")
    temporary.replace(STORE)


def mutate(change):
    with LOCK:
        current = load_unlocked()
        result = change(current)
        write_unlocked(current)
        return result


def shelly_keys(devices: list[dict]) -> set[tuple[str, int]]:
    found = set()
    for device in devices:
        if device["kind"] in ("shelly-gen1", "shelly-gen2"):
            found.add((device["host"], device["switch_id"]))
        for control in device.get("controls") or []:
            if control["kind"] in ("shelly-gen1", "shelly-gen2"):
                found.add((control["host"], control["switch_id"]))
    return found


def http_keys(devices: list[dict]) -> set[tuple[str, str]]:
    found = set()
    for device in devices:
        if device["kind"] == "http-switch":
            found.add((device["host"], device["on_path"]))
        for control in device.get("controls") or []:
            if control["kind"] == "http-switch":
                found.add((control["host"], control["on_path"]))
    return found


def assign_new(items: list[dict], taken_shelly: set, taken_http: set) -> list[dict]:
    added = []
    for item in items:
        if item["kind"] in ("shelly-gen1", "shelly-gen2"):
            key = (item["host"], item["switch_id"])
            if key in taken_shelly:
                continue
            taken_shelly.add(key)
        else:
            key = (item["host"], item["on_path"])
            if key in taken_http:
                continue
            taken_http.add(key)
        item["id"] = uuid.uuid4().hex
        added.append(item)
    return added


def add_device(payload: dict) -> list[dict]:
    device_type = payload.get("type", "shelly")
    name = payload.get("name", "")
    host = payload.get("host", "")
    if not isinstance(device_type, str) or not isinstance(name, str) or not isinstance(host, str):
        raise DeviceError("Enter the device details")
    if device_type == "shelly":
        return add_shelly(host, name)
    if device_type == "http":
        return add_http(payload, name, host)
    if device_type == "controller":
        return [add_controller(name, host)]
    raise DeviceError("Choose a Shelly relay, a switch, or a controller")


def add_shelly(host_raw: str, name_raw: str) -> list[dict]:
    host = parse_shelly_host(host_raw)
    requested = name_raw.strip()[:60]
    found = discover(host, requested)

    def change(current: list[dict]) -> list[dict]:
        added = assign_new(found, shelly_keys(current), http_keys(current))
        if not added:
            raise DeviceError("That relay is already on the page", 409)
        current.extend(added)
        return added

    return mutate(change)


def http_record(payload: dict, name_raw: str, host_raw: str) -> dict:
    on_path = payload.get("on_path", "")
    off_path = payload.get("off_path", "")
    status_path = payload.get("status_path", "")
    status_key = payload.get("status_key", "")
    if not all(isinstance(value, str) for value in (on_path, off_path, status_path, status_key)):
        raise DeviceError("Enter the on, off, and status paths")
    return {
        "name": clean_name(name_raw),
        "host": parse_host(host_raw.strip()),
        "kind": "http-switch",
        "on_path": parse_path(on_path, "on"),
        "off_path": parse_path(off_path, "off"),
        "status_path": parse_path(status_path, "status"),
        "status_key": parse_status_key(status_key),
    }


def add_http(payload: dict, name_raw: str, host_raw: str) -> list[dict]:
    record = http_record(payload, name_raw, host_raw)

    def change(current: list[dict]) -> list[dict]:
        added = assign_new([record], shelly_keys(current), http_keys(current))
        if not added:
            raise DeviceError("That switch is already on the page", 409)
        current.extend(added)
        return added

    return mutate(change)


def add_controller(name_raw: str, endpoint_raw: str) -> dict:
    name = clean_name(name_raw)
    endpoint = parse_endpoint(endpoint_raw)

    def change(current: list[dict]) -> dict:
        if any(item.get("kind") == "controller" and item.get("endpoint") == endpoint["endpoint"] for item in current):
            raise DeviceError("That controller is already on the page", 409)
        record = {
            "id": uuid.uuid4().hex,
            "name": name,
            "host": endpoint["host"],
            "port": endpoint["port"],
            "endpoint": endpoint["endpoint"],
            "kind": "controller",
            "controls": [],
        }
        current.append(record)
        return record

    return mutate(change)


def add_control(device_id: str, payload: dict) -> list[dict]:
    control_type = payload.get("type", "shelly")
    name = payload.get("name", "")
    host = payload.get("host", "")
    if not isinstance(control_type, str) or not isinstance(name, str) or not isinstance(host, str):
        raise DeviceError("Enter the control details")
    if control_type == "shelly":
        prepared = discover(parse_shelly_host(host), name.strip()[:60])
    elif control_type == "http":
        prepared = [http_record(payload, name, host)]
    else:
        raise DeviceError("Choose a Shelly switch or an HTTP switch")

    def change(current: list[dict]) -> list[dict]:
        device = next((item for item in current if item["id"] == device_id), None)
        if device is None or device["kind"] != "controller":
            raise DeviceError("That controller is not on the page", 404)
        added = assign_new(prepared, shelly_keys(current), http_keys(current))
        if not added:
            raise DeviceError("That switch is already on the page", 409)
        device["controls"].extend(added)
        return added

    return mutate(change)


def delete_device(device_id: str) -> None:
    def change(current: list[dict]) -> None:
        kept = [item for item in current if item["id"] != device_id]
        if len(kept) == len(current):
            raise DeviceError("That device is not on the page", 404)
        current[:] = kept

    mutate(change)


def delete_control(device_id: str, control_id: str) -> None:
    def change(current: list[dict]) -> None:
        device = next((item for item in current if item["id"] == device_id), None)
        if device is None or device["kind"] != "controller":
            raise DeviceError("That controller is not on the page", 404)
        kept = [item for item in device["controls"] if item["id"] != control_id]
        if len(kept) == len(device["controls"]):
            raise DeviceError("That control is not on the controller", 404)
        device["controls"] = kept

    mutate(change)


def find_device(device_id: str) -> dict:
    for item in read_devices():
        if item["id"] == device_id:
            return item
    raise DeviceError("That device is not on the page", 404)


def find_control(device_id: str, control_id: str) -> dict:
    device = find_device(device_id)
    if device["kind"] != "controller":
        raise DeviceError("That device has no controls", 404)
    for control in device["controls"]:
        if control["id"] == control_id:
            return control
    raise DeviceError("That control is not on the controller", 404)


def set_switch(switch: dict, on: bool) -> None:
    if switch["kind"] == "shelly-gen2":
        http_call(
            switch["host"],
            "/rpc/Switch.Set?id=%d&on=%s" % (switch["switch_id"], "true" if on else "false"),
            5,
        )
        return
    if switch["kind"] == "shelly-gen1":
        http_call(switch["host"], "/relay/%d?turn=%s" % (switch["switch_id"], "on" if on else "off"), 5)
        return
    http_call(switch["host"], switch["on_path"] if on else switch["off_path"], 5)


def read_switch(switch: dict) -> dict:
    public = {
        "id": switch.get("id"),
        "name": switch["name"],
        "host": switch["host"],
        "kind": switch["kind"],
        "role": "switch",
        "online": False,
        "output": None,
        "temperature_c": None,
        "error": "The device did not answer",
    }
    try:
        if switch["kind"] == "shelly-gen2":
            data = http_json(switch["host"], "/rpc/Switch.GetStatus?id=%d" % switch["switch_id"], 3)
            temperature = data.get("temperature") if isinstance(data.get("temperature"), dict) else {}
            public["output"] = bool(data.get("output"))
            degrees = temperature.get("tC")
            public["temperature_c"] = degrees if isinstance(degrees, (int, float)) else None
            public["switch_id"] = switch["switch_id"]
        elif switch["kind"] == "shelly-gen1":
            data = http_json(switch["host"], "/relay/%d" % switch["switch_id"], 3)
            public["output"] = bool(data.get("ison"))
            public["switch_id"] = switch["switch_id"]
        else:
            data = http_json(switch["host"], switch["status_path"], 3)
            public["output"] = as_bool(lookup_key(data, switch["status_key"]))
        public["online"] = True
        public["error"] = None
    except DeviceError as error:
        if error.status != 502:
            public["online"] = True
            public["error"] = str(error)
    return public


def tcp_open(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=2):
            return True
    except OSError:
        return False


def read_device(device: dict) -> dict:
    if device["kind"] != "controller":
        return read_switch(device)
    controls = device["controls"]
    if controls:
        with ThreadPoolExecutor(max_workers=min(8, len(controls))) as pool:
            rows = list(pool.map(read_switch, controls))
    else:
        rows = []
    return {
        "id": device["id"],
        "name": device["name"],
        "host": device["host"],
        "endpoint": device["endpoint"],
        "kind": "controller",
        "role": "controller",
        "online": tcp_open(device["host"], device["port"]),
        "controls": rows,
        "error": None,
    }


def devices_with_status() -> list[dict]:
    devices = read_devices()
    if not devices:
        return []
    with ThreadPoolExecutor(max_workers=min(8, len(devices))) as pool:
        rows = list(pool.map(read_device, devices))
    counts: dict[str, int] = {}
    for row in rows:
        if row["role"] == "switch" and row["kind"].startswith("shelly"):
            counts[row["host"]] = counts.get(row["host"], 0) + 1
        for control in row.get("controls") or []:
            if control["kind"].startswith("shelly"):
                counts[control["host"]] = counts.get(control["host"], 0) + 1
    for row in rows:
        if row["role"] == "switch" and "switch_id" in row:
            row["channel"] = row["switch_id"] + 1 if counts.get(row["host"], 0) > 1 else None
        for control in row.get("controls") or []:
            if "switch_id" in control:
                control["channel"] = control["switch_id"] + 1 if counts.get(control["host"], 0) > 1 else None
    return rows


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args) -> None:
        print("[%s] %s" % (self.log_date_time_string(), fmt % args), flush=True)

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, payload: dict) -> None:
        self._send(status, json.dumps(payload).encode(), "application/json")

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length < 0 or length > 16000:
            raise DeviceError("The request is too large")
        raw = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(raw.decode())
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise DeviceError("The request is not valid JSON") from error
        if not isinstance(payload, dict):
            raise DeviceError("The request is not valid JSON")
        return payload

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            self._send(200, INDEX.read_bytes(), "text/html; charset=utf-8")
            return
        if path == "/api/devices":
            try:
                self._json(200, {"devices": devices_with_status()})
            except DeviceError as error:
                self._json(error.status, {"error": str(error)})
            return
        self._json(404, {"error": "Not found"})

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        try:
            if path == "/api/devices":
                added = add_device(self._read_json())
                self._json(201, {"added": added})
                return
            control_add = CONTROL_ADD.fullmatch(path)
            if control_add:
                added = add_control(control_add.group(1), self._read_json())
                self._json(201, {"added": added})
                return
            device_cmd = DEVICE_CMD.fullmatch(path)
            if device_cmd:
                device = find_device(device_cmd.group(1))
                if device["kind"] == "controller":
                    raise DeviceError("Add a switch to this controller")
                set_switch(device, device_cmd.group(2) == "on")
                self._json(200, {"ok": True})
                return
            control_cmd = CONTROL_CMD.fullmatch(path)
            if control_cmd:
                control = find_control(control_cmd.group(1), control_cmd.group(2))
                set_switch(control, control_cmd.group(3) == "on")
                self._json(200, {"ok": True})
                return
        except DeviceError as error:
            self._json(error.status, {"error": str(error)})
            return
        self._json(404, {"error": "Not found"})

    def do_DELETE(self) -> None:
        path = urlparse(self.path).path
        try:
            control_item = CONTROL_ITEM.fullmatch(path)
            if control_item:
                delete_control(control_item.group(1), control_item.group(2))
                self._json(200, {"ok": True})
                return
            device_item = DEVICE_ITEM.fullmatch(path)
            if device_item:
                delete_device(device_item.group(1))
                self._json(200, {"ok": True})
                return
        except DeviceError as error:
            self._json(error.status, {"error": str(error)})
            return
        self._json(404, {"error": "Not found"})


def main() -> None:
    read_devices()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print("Controls: http://%s:%s" % (HOST, PORT), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print()
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
