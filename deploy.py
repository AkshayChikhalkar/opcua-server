"""Build the recorder image and start it on the remote PC.

  python deploy.py

The login is read from deploy.local.json. That file stays on this machine.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

import paramiko

ROOT = Path(__file__).resolve().parent
CONFIG_PATH = ROOT / "deploy.local.json"
IMAGE = "opcua-recorders:latest"
UPLOADS = (
    "docker-compose.recorders.yml",
    ".env",
    "ecu.local.json",
    "lynx.local.json",
)


def load_config() -> dict:
    if not CONFIG_PATH.is_file():
        print("Missing deploy.local.json. It needs host, user, password, and remote_dir.")
        sys.exit(1)
    config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    missing = [key for key in ("host", "user", "password", "remote_dir") if not config.get(key)]
    if missing:
        print("deploy.local.json is missing: %s" % ", ".join(missing))
        sys.exit(1)
    return config


def run_local(command: list[str]) -> None:
    print("+", " ".join(command), flush=True)
    subprocess.run(command, cwd=ROOT, check=True)


def remote_command(client: paramiko.SSHClient, command: str, timeout: int = 600) -> None:
    print("$", command, flush=True)
    _stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
    out = stdout.read().decode("utf-8", "replace")
    err = stderr.read().decode("utf-8", "replace")
    code = stdout.channel.recv_exit_status()
    if out:
        print(out, end="" if out.endswith("\n") else "\n")
    if err:
        print(err, end="" if err.endswith("\n") else "\n", file=sys.stderr)
    if code != 0:
        sys.exit(code)


def main() -> None:
    config = load_config()
    for name in UPLOADS:
        if not (ROOT / name).is_file():
            print("Missing %s" % name)
            sys.exit(1)

    run_local(["docker", "build", "-t", IMAGE, "."])
    with tempfile.NamedTemporaryFile(prefix="opcua-recorders-", suffix=".tar", delete=False) as handle:
        tar_path = Path(handle.name)
    try:
        print("+ docker save %s" % IMAGE, flush=True)
        with tar_path.open("wb") as handle:
            subprocess.run(["docker", "save", IMAGE], stdout=handle, cwd=ROOT, check=True)
        print("Image archive is %.0f MB" % (tar_path.stat().st_size / 1e6), flush=True)

        remote_dir = str(config["remote_dir"]).replace("\\", "/")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        print("Connecting to %s" % config["host"], flush=True)
        client.connect(
            config["host"],
            username=config["user"],
            password=config["password"],
            timeout=20,
            allow_agent=False,
            look_for_keys=False,
        )
        sftp = client.open_sftp()
        try:
            sftp.mkdir(remote_dir)
        except OSError:
            pass

        def progress(sent: int, total: int) -> None:
            if total and (sent == total or sent % (25 * 1024 * 1024) < 1024 * 1024):
                print("  uploaded %.0f / %.0f MB" % (sent / 1e6, total / 1e6), flush=True)

        for name in UPLOADS:
            print("upload", name, flush=True)
            sftp.put(str(ROOT / name), remote_dir + "/" + name)
        print("upload image", flush=True)
        remote_tar = remote_dir + "/opcua-recorders.tar"
        sftp.put(str(tar_path), remote_tar, callback=progress)
        sftp.close()

        windows_dir = remote_dir.replace("/", "\\")
        remote_command(client, "docker load -i %s\\opcua-recorders.tar" % windows_dir)
        remote_command(client, "del /q %s\\opcua-recorders.tar" % windows_dir)
        remote_command(
            client,
            "cd /d %s && docker compose -f docker-compose.recorders.yml up -d" % windows_dir,
        )
        remote_command(client, "docker compose -f %s\\docker-compose.recorders.yml ps" % windows_dir)
        remote_command(client, "docker logs --tail 30 opcua-recorders-recorders-1")
        client.close()
    finally:
        tar_path.unlink(missing_ok=True)
    print("Deployed.", flush=True)


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as exc:
        sys.exit(exc.returncode)
    except KeyboardInterrupt:
        print("\nStopped.")
        sys.exit(1)
