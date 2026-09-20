#!/usr/bin/env python3
"""Run synthetic scans through an isolated real Rspamd daemon (Linux/CI)."""

import getpass
import grp
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.mock_jev import create_server  # noqa: E402
from tools.summarize import read_records  # noqa: E402


def wait_for_daemon(process, port):
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("Rspamd exited during startup")
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/ping", timeout=0.2) as response:
                if response.status == 200:
                    return
        except (OSError, urllib.error.URLError):
            time.sleep(0.1)
    raise RuntimeError("Rspamd did not become ready")


def main():
    if not shutil.which("rspamd") or not shutil.which("rspamadm"):
        raise SystemExit("Native smoke test requires rspamd and rspamadm (run on Linux or CI).")
    root = Path(__file__).resolve().parents[1]
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    with tempfile.TemporaryDirectory(prefix="jev-smoke-") as directory:
        work = Path(directory)
        mock = create_server(port=0)
        thread = threading.Thread(target=mock.serve_forever, daemon=True)
        thread.start()
        config = work / "rspamd.conf"
        bootstrap = work / "bootstrap.lua"
        bootstrap.write_text("""
local id = rspamd_config:register_symbol({
  name = 'GPT_CHECK', type = 'postfilter', priority = 5,
  callback = function(task) task:insert_result('GPT_HAM', 1.0, '0.1') end,
})
rspamd_config:register_symbol({
  name = 'GPT_HAM', type = 'virtual', parent = id, score = -2.0,
})
""")
        config.write_text(f"""
options {{
  pidfile = "{work / 'rspamd.pid'}";
  tempdir = "{work}";
  hs_cache_dir = "{work}";
}}
logging {{
  type = "console";
  level = "info";
}}
actions {{
  reject = 15;
  add_header = 6;
  greylist = 4;
}}
lua = "{bootstrap}";
modules {{
  path = "{root / 'rspamd'}";
}}
worker "normal" {{
  bind_socket = "127.0.0.1:{port}";
  count = 1;
}}
jev {{
  enabled = true;
  mode = "mock";
  url = "http://127.0.0.1:{mock.server_port}/v1/systemone";
  require_gpt = true;
  sample_rate = 1;
  requests_per_second = 1000;
  cooldown = 0.1;
  timeout = 0.3;
}}
""")
        process = None
        log_path = work / "daemon.log"
        try:
            subprocess.run(["rspamadm", "configtest", "-c", str(config)], check=True)
            with log_path.open("w") as daemon_log:
                process = subprocess.Popen([
                    "rspamd", "-f", "-c", str(config),
                    "-u", getpass.getuser(), "-g", grp.getgrgid(os.getgid()).gr_name,
                ], stdout=daemon_log, stderr=subprocess.STDOUT)
                wait_for_daemon(process, port)
                outcomes = ("ham", "spam", "phishing", "uncertain", "malformed", "429", "500", "529", "timeout")
                for index, outcome in enumerate(outcomes):
                    mock.outcome = "ham" if outcome == "timeout" else outcome
                    mock.delay = 0.8 if outcome == "timeout" else 0
                    message = (
                        f"From: sender@example.test\r\nTo: recipient@example.test\r\n"
                        f"Subject: Synthetic Jev smoke {index}\r\n"
                        f"Message-ID: <jev-smoke-{index}@example.test>\r\n"
                        f"MIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
                        f"<p>Synthetic fixture {index}, no real email.</p>"
                        '<a href="https://example.test/invoice">View invoice</a>\r\n'
                    ).encode()
                    request = urllib.request.Request(
                        f"http://127.0.0.1:{port}/checkv2", data=message,
                        headers={"Content-Type": "text/plain", "Rcpt": "recipient@example.test"},
                    )
                    with urllib.request.urlopen(request, timeout=10) as response:
                        result = json.load(response)
                    expected = "JEV_" + (outcome.upper() if outcome in {
                        "ham", "spam", "phishing", "uncertain"
                    } else "ERROR")
                    symbols = result.get("symbols", {})
                    if expected not in symbols:
                        raise AssertionError(f"{outcome}: expected {expected}, got {result}")
                    if result["score"] != -2 or result["action"] != "no action":
                        raise AssertionError(f"shadow changed existing outcome: {result}")
                    if any(info["score"] != 0 for name, info in symbols.items() if name.startswith("JEV_")):
                        raise AssertionError("nonzero Jev symbol")
                    time.sleep(0.15)
                process.terminate()
                process.wait(timeout=10)
            records = list(read_records(io_lines(log_path)))
            if len(records) != len(outcomes) or sum(record["status"] == "ok" for record in records) != 4:
                raise AssertionError(f"expected {len(outcomes)} paired records, got {records}")
            if any(record["baseline"]["verdict"] != "ham" for record in records):
                raise AssertionError("GPT postfilter dependency did not finish before Jev")
            print(f"Native Rspamd smoke passed: {len(outcomes)} scans, unchanged score/action, paired logs.")
        except BaseException:
            if log_path.exists():
                print(log_path.read_text(), file=sys.stderr)
            raise
        finally:
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            mock.shutdown()
            mock.server_close()
            thread.join()


def io_lines(path):
    return path.read_text().splitlines()


if __name__ == "__main__":
    main()
