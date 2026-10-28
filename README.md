# OPC UA ECU client

Python client for the Phoenix Contact OPC UA server on the Prüfwand controller.

The controller is an OPC UA server at `opc.tcp://192.168.1.10:4840` (`Safety-Control-ECU`). It requires a signed session. Username, password, and IP are stored in `ecu.local.json`. That file is gitignored.

`subscribe` chooses the variables. A rule can set `namespace`, `identifier` (a name prefix), `contains`, or `node_id`. The saved rules keep the server state, the device name, and every PLC variable in namespace 6.

```json
"subscribe": [
  { "node_id": "i=2259" },
  { "namespace": 6, "contains": "_ERR" }
]
```

## Setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

The controller is on `192.168.1.0/24`. This PC reaches it through the Tailscale subnet route advertised by `DESKTOP-R57P7PK`.

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
