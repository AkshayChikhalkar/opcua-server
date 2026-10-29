let seen = {};
let scans = 0;
let victron = 0;
let scanError = "";

function toHex(data) {
  let hex = "";
  let i = 0;
  for (i = 0; i < data.length; i++) {
    let h = (data.charCodeAt(i) & 255).toString(16);
    if (h.length < 2) {
      h = "0" + h;
    }
    hex = hex + h;
  }
  return hex;
}

function manufacturer(res) {
  if (typeof res.manufacturer_data === "undefined" || res.manufacturer_data === null) {
    return null;
  }
  if (typeof res.manufacturer_data["02e1"] === "string") {
    return res.manufacturer_data["02e1"];
  }
  if (typeof res.manufacturer_data["02E1"] === "string") {
    return res.manufacturer_data["02E1"];
  }
  return null;
}

function scanCB(ev, res) {
  if (ev !== BLE.Scanner.SCAN_RESULT) {
    return;
  }
  scans = scans + 1;
  if (typeof res === "undefined" || res === null) {
    return;
  }
  let raw = manufacturer(res);
  if (raw === null || raw.length < 8) {
    return;
  }
  if (typeof res.addr !== "string") {
    return;
  }
  victron = victron + 1;
  let name = "";
  if (typeof res.local_name === "string") {
    name = res.local_name;
  }
  seen[res.addr] = {
    mac: res.addr,
    name: name,
    rssi: res.rssi,
    hex: toHex(raw)
  };
}

function startScan() {
  let bleConfig = Shelly.getComponentConfig("ble");
  if (typeof bleConfig.enable !== "undefined" && bleConfig.enable === false) {
    scanError = "bluetooth disabled";
    return;
  }
  let started = BLE.Scanner.Start(
    { duration_ms: BLE.Scanner.INFINITE_SCAN, active: false },
    scanCB
  );
  if (started === false) {
    scanError = "scanner failed to start";
  }
}

HTTPServer.registerEndpoint("lynx", function (request, response) {
  response.code = 200;
  response.headers = { "Content-Type": "application/json" };
  response.body = JSON.stringify({
    error: scanError,
    scans: scans,
    victron: victron,
    devices: seen
  });
  response.send();
});

startScan();
