# OPC UA ECU client

Python client for the Phoenix Contact OPC UA server on the Prüfwand controller.

The controller is an OPC UA server at `opc.tcp://192.168.1.10:4840` (`Safety-Control-ECU`). It requires a signed session. Username, password, IP, and the PLC node ids are stored in `ecu.local.json`. That file is gitignored.

## Setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

This PC is on `192.168.140.0/24`. The controller is on `192.168.1.0/24`. A static route through the dual-homed PC is required:

```powershell
route add 192.168.1.0 mask 255.255.255.0 192.168.140.21
```

## Connect

`ecu.local.json` is read automatically:

```powershell
python ecu_client.py
```

Override it on the command line when needed:

```powershell
python ecu_client.py --url opc.tcp://192.168.1.10:4840 --user admin --password <password>
```

Record 5 minutes to `recordings/session-YYYYMMDD-HHMMSS.jsonl`:

```powershell
python ecu_client.py --minutes 5
```

The client creates `certs/client_cert.der` and `certs/client_key.pem` on first login. Certificates and recordings stay on this machine and are not committed.

Scan the local subnets instead of using the saved controller:

```powershell
python ecu_client.py --scan
python ecu_client.py --scan --subnet 192.168.1.0/24
```
