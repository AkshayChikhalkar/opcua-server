"""Record Lynx Smart BMS instant-readout values via the Shelly Pro 1.

The Shelly sits near the BMS, hears its Bluetooth broadcast, and the
recorder on this PC polls that broadcast over Wi-Fi. Copy
lynx.local.example.json to lynx.local.json and paste the advertisement
key from VictronConnect before decoded values are stored.

  python lynx_recorder.py --install
  python lynx_recorder.py --discover
  python lynx_recorder.py
"""

from __future__ import annotations

import argparse
import json
import os
import struct
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import psycopg
from victron_ble.devices import detect_device_type
from victron_ble.exceptions import AdvertisementKeyMismatchError

ROOT = Path(__file__).resolve().parent
CONFIG_PATH = ROOT / "lynx.local.json"
SCRIPT_PATH = ROOT / "shelly" / "lynx_scan.js"
DEFAULT_SHELLY = "http://192.168.140.36"
SCRIPT_NAME = "lynx-ble"

READOUT_NAMES = {
    0x1: "solar charger",
    0x2: "battery monitor",
    0x3: "inverter",
    0x4: "DC-DC converter",
    0x5: "Smart Lithium",
    0x8: "AC charger",
    0x9: "Smart BatteryProtect",
    0xA: "Lynx Smart BMS",
    0xB: "Multi RS",
    0xC: "VE.Bus",
    0xD: "DC energy meter",
    0xF: "Orion XS",
}

FIELD_NAMES = {
    "voltage": "voltage_v",
    "current": "current_a",
    "soc": "soc_pct",
    "consumed_ah": "consumed_ah",
    "remaining_mins": "remaining_min",
    "battery_temperature": "battery_temperature_c",
    "temperature": "temperature_c",
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


def normalise_mac(value: str) -> str:
    hex_chars = "".join(char for char in value.lower() if char in "0123456789abcdef")
    if len(hex_chars) != 12:
        return value.strip().lower()
    return ":".join(hex_chars[index : index + 2] for index in range(0, 12, 2))


def load_config() -> dict:
    if not CONFIG_PATH.is_file():
        return {"shelly": DEFAULT_SHELLY, "interval_seconds": 5, "devices": {}}
    config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    devices = {}
    for mac, item in config.get("devices", {}).items():
        devices[normalise_mac(mac)] = item
    config["devices"] = devices
    config.setdefault("shelly", DEFAULT_SHELLY)
    config.setdefault("interval_seconds", 5)
    return config


def rpc(shelly: str, method: str, params: dict | None = None, timeout: float = 8) -> dict:
    payload = json.dumps({"id": 1, "method": method, "params": params or {}}).encode()
    request = urllib.request.Request(
        shelly.rstrip("/") + "/rpc",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = json.loads(response.read().decode())
    if "error" in body:
        raise RuntimeError("%s: %s" % (method, body["error"]))
    return body.get("result", {})


def install_script(shelly: str) -> int:
    code = SCRIPT_PATH.read_text(encoding="utf-8")
    listed = rpc(shelly, "Script.List")
    scripts = listed.get("scripts", listed if isinstance(listed, list) else [])
    script_id = None
    for item in scripts:
        if item.get("name") == SCRIPT_NAME:
            script_id = item["id"]
            break
    if script_id is None:
        created = rpc(shelly, "Script.Create", {"name": SCRIPT_NAME})
        script_id = created["id"]
    else:
        rpc(shelly, "Script.Stop", {"id": script_id})
    rpc(shelly, "Script.PutCode", {"id": script_id, "code": code, "append": False}, timeout=20)
    rpc(shelly, "Script.SetConfig", {"id": script_id, "config": {"enable": True}})
    ble = rpc(shelly, "BLE.SetConfig", {"config": {"enable": True}})
    status = rpc(shelly, "Shelly.GetStatus")
    restart_required = bool(status.get("sys", {}).get("restart_required")) or bool(
        ble.get("restart_required")
    )
    if restart_required:
        print("Bluetooth is enabled. The Shelly must restart before the scan runs.")
        print("The relay is left as it is. Restart it when the load can drop for a few seconds:")
        print("  python lynx_recorder.py --restart-shelly")
        return script_id
    rpc(shelly, "Script.Start", {"id": script_id})
    print("Lynx scan script %s is running on %s" % (script_id, shelly))
    return script_id


def restart_shelly(shelly: str) -> None:
    print("Restarting %s. Its relay opens until the device is back." % shelly)
    try:
        rpc(shelly, "Shelly.Reboot", timeout=5)
    except (urllib.error.URLError, TimeoutError, OSError):
        pass
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        time.sleep(3)
        try:
            rpc(shelly, "Shelly.GetDeviceInfo", timeout=4)
        except (urllib.error.URLError, TimeoutError, OSError, RuntimeError):
            continue
        break
    else:
        raise RuntimeError("Shelly did not come back after restart")
    listed = rpc(shelly, "Script.List")
    scripts = listed.get("scripts", [])
    for item in scripts:
        if item.get("name") == SCRIPT_NAME and not item.get("running"):
            rpc(shelly, "Script.Start", {"id": item["id"]})
    print("Shelly is back and the scan script is started.")


def fetch_sightings(shelly: str, script_id: int) -> dict:
    request = urllib.request.Request(
        "%s/script/%s/lynx" % (shelly.rstrip("/"), script_id),
        method="GET",
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.loads(response.read().decode())


def script_id_for(shelly: str) -> int | None:
    listed = rpc(shelly, "Script.List")
    for item in listed.get("scripts", []):
        if item.get("name") == SCRIPT_NAME:
            return item["id"]
    return None


def payload_bytes(hex_text: str) -> bytes:
    raw = bytes.fromhex(hex_text)
    if len(raw) >= 2 and raw[0] == 0xE1 and raw[1] == 0x02:
        raw = raw[2:]
    return raw


def describe(raw: bytes) -> str:
    if len(raw) < 5:
        return "short packet (%s bytes)" % len(raw)
    model_id, mode = struct.unpack_from("<HB", raw, 2)
    kind = READOUT_NAMES.get(mode, "readout 0x%X" % mode)
    return "%s, model 0x%04X" % (kind, model_id)


def numeric_fields(parsed) -> dict[str, float]:
    values: dict[str, float] = {}
    for name in dir(parsed):
        if not name.startswith("get_") or name in ("get_model_name",):
            continue
        try:
            value = getattr(parsed, name)()
        except Exception:
            continue
        if isinstance(value, bool) or value is None or isinstance(value, (dict, list, tuple)):
            continue
        if not isinstance(value, (int, float)):
            continue
        key = name[4:]
        values[FIELD_NAMES.get(key, key)] = float(value)
    voltage = values.get("voltage_v")
    current = values.get("current_a")
    if voltage is not None and current is not None:
        values["power_w"] = voltage * current
    return values


def decode(raw: bytes, key: str):
    device_type = detect_device_type(raw)
    if device_type is None:
        raise ValueError("unrecognised Victron broadcast")
    return device_type(key).parse(raw)


class Store:
    def __init__(self, connection: psycopg.Connection) -> None:
        self.connection = connection
        self.controllers: dict[str, int] = {}
        self.signals: dict[tuple[int, str], int] = {}
        self.lock = threading.Lock()

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

    def controller(self, endpoint: str, name: str) -> int:
        cached = self.controllers.get(endpoint)
        if cached is not None:
            return cached
        with self.connection.cursor() as cur:
            cur.execute(
                """
                INSERT INTO controllers (name, endpoint)
                VALUES (%s, %s)
                ON CONFLICT (endpoint) DO UPDATE SET name = EXCLUDED.name
                RETURNING id
                """,
                (name, endpoint),
            )
            controller_id = cur.fetchone()[0]
        self.controllers[endpoint] = controller_id
        return controller_id

    def signal(self, controller_id: int, identifier: str) -> int:
        key = (controller_id, identifier)
        cached = self.signals.get(key)
        if cached is not None:
            return cached
        with self.connection.cursor() as cur:
            cur.execute(
                """
                INSERT INTO signals (controller_id, namespace, identifier, name)
                VALUES (%s, 0, %s, %s)
                ON CONFLICT (controller_id, namespace, identifier)
                DO UPDATE SET name = EXCLUDED.name
                RETURNING id
                """,
                (controller_id, identifier, identifier),
            )
            signal_id = cur.fetchone()[0]
        self.signals[key] = signal_id
        return signal_id

    def write(self, endpoint: str, name: str, values: dict[str, float], rssi: float | None) -> None:
        when = datetime.now(timezone.utc)
        with self.lock:
            controller_id = self.controller(endpoint, name)
            samples = dict(values)
            if rssi is not None:
                samples["rssi_dbm"] = float(rssi)
            with self.connection.cursor() as cur:
                for identifier, value in samples.items():
                    signal_id = self.signal(controller_id, identifier)
                    cur.execute(
                        """
                        INSERT INTO samples (time, received_at, signal_id, value_num, value_text, status)
                        VALUES (%s, %s, %s, %s, NULL, NULL)
                        """,
                        (when, when, signal_id, value),
                    )
                    cur.execute(
                        """
                        INSERT INTO latest (signal_id, time, value_num, value_text, status)
                        VALUES (%s, %s, %s, NULL, NULL)
                        ON CONFLICT (signal_id) DO UPDATE SET
                            time = EXCLUDED.time,
                            value_num = EXCLUDED.value_num,
                            value_text = NULL,
                            status = NULL
                        """,
                        (signal_id, when, value),
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

    def mark_offline(self) -> None:
        if not self.controllers:
            return
        with self.lock:
            with self.connection.cursor() as cur:
                for controller_id in self.controllers.values():
                    cur.execute(
                        """
                        UPDATE recorder_status
                        SET listening = false, last_seen = now()
                        WHERE controller_id = %s
                        """,
                        (controller_id,),
                    )


def device_settings(config: dict, mac: str) -> dict | None:
    return config.get("devices", {}).get(normalise_mac(mac))


def real_key(item: dict | None) -> str | None:
    if not item:
        return None
    key = str(item.get("key", "")).strip().lower().replace(" ", "")
    if len(key) != 32 or any(char not in "0123456789abcdef" for char in key):
        return None
    return key


def print_sighting(mac: str, item: dict, note: str) -> None:
    name = item.get("name") or "(no name)"
    rssi = item.get("rssi")
    print("%s  %s  rssi %s  %s" % (normalise_mac(mac), name, rssi, note))


def poll_once(config: dict, store: Store | None, script_id: int) -> int:
    shelly = config["shelly"]
    try:
        report = fetch_sightings(shelly, script_id)
    except urllib.error.HTTPError as error:
        print("Shelly scan page returned %s. Run: python lynx_recorder.py --install" % error.code)
        return 0
    if report.get("error"):
        print("Shelly scan: %s" % report["error"])
        return 0
    devices = report.get("devices") or {}
    if not devices:
        print(
            "No Victron broadcast yet (%s Bluetooth packets seen). "
            "The Shelly has to be near the Lynx, and Instant Readout has to be on."
            % report.get("scans", 0)
        )
        return 0
    written = 0
    for mac, item in devices.items():
        try:
            raw = payload_bytes(item.get("hex") or "")
        except ValueError:
            print_sighting(mac, item, "unreadable packet")
            continue
        summary = describe(raw)
        settings = device_settings(config, mac)
        key = real_key(settings)
        if key is None:
            print_sighting(mac, item, summary + " — advertisement key missing")
            continue
        try:
            parsed = decode(raw, key)
        except AdvertisementKeyMismatchError:
            print_sighting(mac, item, summary + " — advertisement key does not match")
            continue
        except Exception as exc:
            print_sighting(mac, item, summary + " — %s" % exc)
            continue
        values = numeric_fields(parsed)
        name = (settings or {}).get("name") or item.get("name") or parsed.get_model_name()
        endpoint = "ble://" + normalise_mac(mac)
        if store is not None:
            store.write(endpoint, name, values, item.get("rssi"))
            written += 1
        readable = ", ".join("%s=%s" % (field, values[field]) for field in sorted(values))
        print_sighting(mac, item, readable)
    return written


def discover(config: dict, seconds: float) -> None:
    shelly = config["shelly"]
    script_id = script_id_for(shelly)
    if script_id is None:
        script_id = install_script(shelly)
    deadline = time.monotonic() + seconds
    last = ""
    while time.monotonic() < deadline:
        try:
            report = fetch_sightings(shelly, script_id)
        except urllib.error.HTTPError as error:
            print("Scan page returned %s" % error.code)
            return
        text = json.dumps(report, sort_keys=True)
        if text != last:
            last = text
            devices = report.get("devices") or {}
            print(
                "scans=%s victron=%s devices=%s error=%s"
                % (report.get("scans"), report.get("victron"), len(devices), report.get("error") or "")
            )
            for mac, item in devices.items():
                try:
                    raw = payload_bytes(item.get("hex") or "")
                    note = describe(raw)
                except ValueError:
                    note = "bad hex"
                print_sighting(mac, item, note)
        time.sleep(2)


def record(config: dict) -> None:
    shelly = config["shelly"]
    script_id = script_id_for(shelly)
    if script_id is None:
        raise RuntimeError("Scan script is not installed. Run: python lynx_recorder.py --install")
    store = Store.connect()
    interval = float(config.get("interval_seconds") or 5)
    print("Recording Lynx broadcasts from %s every %ss. Ctrl+C stops." % (shelly, interval))
    try:
        while True:
            poll_once(config, store, script_id)
            time.sleep(interval)
    except KeyboardInterrupt:
        print()
    finally:
        store.mark_offline()
        store.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Record Lynx Smart BMS values via a Shelly Bluetooth scan.")
    parser.add_argument("--install", action="store_true", help="Upload the scan script and enable Bluetooth")
    parser.add_argument("--restart-shelly", action="store_true", help="Restart the Shelly so Bluetooth starts")
    parser.add_argument("--discover", action="store_true", help="Print nearby Victron broadcasts and exit")
    parser.add_argument("--seconds", type=float, default=20, help="How long --discover listens")
    args = parser.parse_args()
    config = load_config()
    shelly = config["shelly"]
    if args.install:
        install_script(shelly)
        return
    if args.restart_shelly:
        restart_shelly(shelly)
        return
    if args.discover:
        discover(config, args.seconds)
        return
    record(config)


if __name__ == "__main__":
    main()
