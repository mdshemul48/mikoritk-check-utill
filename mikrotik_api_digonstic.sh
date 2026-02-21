#!/bin/bash
# MikroTik API Diagnostic Center
# Usage:
#   Direct:  ./mikrotik_api_digonstic.sh <ip> <port> <user> <password>
#   Remote:  curl -s https://scripts.yetfix.com/mikrotik-api-diagnostic-center.sh | bash -s -- <ip> <port> <user> <password>

set -e

if [ $# -ne 4 ]; then
    echo "Usage: $0 <ip> <port> <username> <password>"
    exit 1
fi

# Find Python 3
PYTHON=""
for cmd in python3 python; do
    if command -v "$cmd" &>/dev/null && "$cmd" -c "import sys; assert sys.version_info >= (3,8)" 2>/dev/null; then
        PYTHON="$cmd"
        break
    fi
done

if [ -z "$PYTHON" ]; then
    echo "Error: Python 3.8+ is required but not found."
    echo "Install it with:  apt install python3  (or)  brew install python3"
    exit 1
fi

# Ensure pip is available
if ! "$PYTHON" -m pip --version &>/dev/null; then
    echo -e "\033[33m⚡ pip not found — installing pip…\033[0m"
    if command -v apt-get &>/dev/null; then
        sudo apt-get update -qq && sudo apt-get install -y -qq python3-pip 2>/dev/null
    elif command -v yum &>/dev/null; then
        sudo yum install -y python3-pip 2>/dev/null
    elif command -v dnf &>/dev/null; then
        sudo dnf install -y python3-pip 2>/dev/null
    elif command -v apk &>/dev/null; then
        sudo apk add --quiet py3-pip 2>/dev/null
    fi
    if ! "$PYTHON" -m pip --version &>/dev/null; then
        echo -e "\033[33m⚡ Trying ensurepip…\033[0m"
        "$PYTHON" -m ensurepip --upgrade 2>/dev/null || \
            curl -sS https://bootstrap.pypa.io/get-pip.py | "$PYTHON" -
    fi
    if ! "$PYTHON" -m pip --version &>/dev/null; then
        echo -e "\033[31m✗ Could not install pip. Install it manually:\033[0m"
        echo "    apt install python3-pip   (or)   curl https://bootstrap.pypa.io/get-pip.py | python3 -"
        exit 1
    fi
    echo -e "\033[32m✓ pip installed.\033[0m"
fi

# Install textual if missing
if ! "$PYTHON" -c "import textual" 2>/dev/null; then
    echo -e "\033[33m⚡ Installing dependencies (first run only)…\033[0m"
    "$PYTHON" -m pip install textual -q 2>/dev/null || "$PYTHON" -m pip install --user textual -q
    echo -e "\033[32m✓ Done.\033[0m"
fi

# Ensure traceroute is available for the traceroute panel
if ! command -v traceroute &>/dev/null; then
    echo -e "\033[33m⚡ traceroute not found — installing…\033[0m"
    if command -v apt-get &>/dev/null; then
        sudo apt-get update -qq && sudo apt-get install -y -qq traceroute 2>/dev/null
    elif command -v yum &>/dev/null; then
        sudo yum install -y traceroute 2>/dev/null
    elif command -v dnf &>/dev/null; then
        sudo dnf install -y traceroute 2>/dev/null
    elif command -v apk &>/dev/null; then
        sudo apk add --quiet traceroute 2>/dev/null
    elif command -v brew &>/dev/null; then
        brew install traceroute 2>/dev/null
    fi

    if ! command -v traceroute &>/dev/null; then
        echo -e "\033[31m✗ Could not install traceroute automatically.\033[0m"
        echo "  The traceroute panel will show 'traceroute not found' until installed."
    else
        echo -e "\033[32m✓ traceroute installed.\033[0m"
    fi
fi

# Write Python code to a temp file so stdin stays connected to the terminal
_TMPPY=$(mktemp /tmp/mikrotik_monitor_XXXXXXXX)
mv "$_TMPPY" "${_TMPPY}.py"
_TMPPY="${_TMPPY}.py"
trap 'rm -f "$_TMPPY"' EXIT

cat > "$_TMPPY" << 'PYTHON_SCRIPT'
"""MikroTik TUI Monitor — comprehensive router monitoring dashboard."""

import binascii
import hashlib
import os
import random
import re
import socket
import string
import struct
import subprocess
import sys
import threading
import time
from typing import Dict, List, Optional, Tuple

from rich.text import Text
from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import DataTable, Footer, Header, Static


# ── MikroTik API Protocol ──────────────────────────────────────────────────


class MikroTikAPI:
    """Low-level MikroTik RouterOS API client (binary protocol)."""

    def __init__(self, host: str, port: int, timeout: float = 10):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock: Optional[socket.socket] = None
        self.connected = False
        self.logged_in = False
        self.latency_ms: float = 0
        self.raw_log: List[Dict] = []

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        t0 = time.monotonic()
        self.sock.connect((self.host, self.port))
        self.latency_ms = (time.monotonic() - t0) * 1000
        self.connected = True
        self.raw_log.append({
            "ts": time.strftime("%H:%M:%S"),
            "cmd": "TCP connect",
            "elapsed_ms": round(self.latency_ms, 1),
            "rows": 0,
            "error": None,
            "sentences": [],
            "info": f"{self.host}:{self.port}",
        })

    def disconnect(self):
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
        self.connected = False
        self.logged_in = False

    @staticmethod
    def _encode_length(length: int) -> bytes:
        if length < 0x80:
            return struct.pack("!B", length)
        if length < 0x4000:
            return struct.pack("!H", length | 0x8000)
        if length < 0x200000:
            return struct.pack("!I", length | 0xC00000)[1:]
        if length < 0x10000000:
            return struct.pack("!I", length | 0xE0000000)
        return b"\xf0" + struct.pack("!I", length)

    def _recv(self, n: int) -> Optional[bytes]:
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

    def _read_length(self) -> Optional[int]:
        b = self._recv(1)
        if not b:
            return None
        v = b[0]
        if v < 0x80:
            return v
        if v < 0xC0:
            b2 = self._recv(1)
            return ((v & 0x3F) << 8) | b2[0] if b2 else None
        if v < 0xE0:
            r = self._recv(2)
            return ((v & 0x1F) << 16) | (r[0] << 8) | r[1] if r else None
        if v < 0xF0:
            r = self._recv(3)
            if not r:
                return None
            return ((v & 0x0F) << 24) | (r[0] << 16) | (r[1] << 8) | r[2]
        r = self._recv(4)
        if not r:
            return None
        return (r[0] << 24) | (r[1] << 16) | (r[2] << 8) | r[3]

    def _send_sentence(self, words: List[str]):
        for word in words:
            raw = word.encode("utf-8")
            self.sock.sendall(self._encode_length(len(raw)) + raw)
        self.sock.sendall(b"\x00")

    def _read_sentence(self) -> Optional[List[str]]:
        words: List[str] = []
        while True:
            try:
                length = self._read_length()
            except socket.timeout:
                return None
            if length is None:
                return None
            if length == 0:
                return words
            data = self._recv(length)
            if data is None:
                return None
            words.append(data.decode("utf-8", errors="replace"))

    def login(self, user: str, password: str) -> Tuple[bool, str]:
        """Authenticate — auto-detects old (challenge) vs new (plaintext) style."""
        t0 = time.monotonic()
        raw_sentences: List[List[str]] = []

        self._send_sentence(["/login", f"=name={user}", f"=password={password}"])
        resp = self._read_sentence()
        if resp is not None:
            raw_sentences.append(resp)

        if resp is None:
            self._log_login(t0, raw_sentences, None, "No response (timeout)")
            return False, "No response (timeout)"

        if resp[0] == "!done" and not any(w.startswith("=ret=") for w in resp):
            self.logged_in = True
            self._log_login(t0, raw_sentences, "RouterOS 6.43+", None)
            return True, "RouterOS 6.43+"

        challenge = next((w[5:] for w in resp if w.startswith("=ret=")), None)
        if challenge:
            md5 = hashlib.md5(
                b"\x00" + password.encode() + binascii.unhexlify(challenge)
            )
            self._send_sentence(
                ["/login", f"=name={user}", f"=response=00{md5.hexdigest()}"]
            )
            r2 = self._read_sentence()
            if r2 is not None:
                raw_sentences.append(r2)
            if r2 and r2[0] == "!done":
                self.logged_in = True
                self._log_login(t0, raw_sentences, "challenge-response", None)
                return True, "challenge-response"
            err = f"Challenge rejected: {r2}"
            self._log_login(t0, raw_sentences, None, err)
            return False, err

        if resp[0] in ("!trap", "!fatal"):
            msg = next(
                (w.split("=message=", 1)[1] for w in resp if "=message=" in w),
                str(resp),
            )
            self._log_login(t0, raw_sentences, None, msg)
            return False, msg

        err = f"Unexpected: {resp}"
        self._log_login(t0, raw_sentences, None, err)
        return False, err

    def _log_login(self, t0: float, sentences: List[List[str]],
                   method: Optional[str], error: Optional[str]):
        elapsed = (time.monotonic() - t0) * 1000
        self.raw_log.append({
            "ts": time.strftime("%H:%M:%S"),
            "cmd": "/login",
            "elapsed_ms": round(elapsed, 1),
            "rows": 0,
            "error": error,
            "sentences": sentences,
            "info": method,
        })

    def command(self, *words: str) -> List[Dict[str, str]]:
        """Send API command; return list of attribute dicts (one per !re)."""
        cmd_name = words[0] if words else "?"
        t0 = time.monotonic()
        raw_sentences: List[List[str]] = []
        self._send_sentence(list(words))
        rows: List[Dict[str, str]] = []
        error_msg = None
        while True:
            sentence = self._read_sentence()
            if sentence is None:
                break
            raw_sentences.append(sentence)
            tag = sentence[0]
            attrs: Dict[str, str] = {}
            for w in sentence[1:]:
                if w.startswith("="):
                    kv = w[1:].split("=", 1)
                    if len(kv) == 2:
                        attrs[kv[0]] = kv[1]
            if tag == "!re":
                rows.append(attrs)
            elif tag == "!done":
                break
            elif tag in ("!trap", "!fatal"):
                error_msg = attrs.get("message", str(sentence))
                while True:
                    tail = self._read_sentence()
                    if tail is None or tail[0] == "!done":
                        if tail:
                            raw_sentences.append(tail)
                        break
                break
        elapsed = (time.monotonic() - t0) * 1000
        self.raw_log.append({
            "ts": time.strftime("%H:%M:%S"),
            "cmd": cmd_name,
            "elapsed_ms": round(elapsed, 1),
            "rows": len(rows),
            "error": error_msg,
            "sentences": raw_sentences,
        })
        if error_msg:
            raise RuntimeError(error_msg)
        return rows

    def get_identity(self) -> str:
        try:
            r = self.command("/system/identity/print")
            return r[0].get("name", "?") if r else "?"
        except Exception:
            return "?"

    def get_resource(self) -> Dict[str, str]:
        try:
            r = self.command("/system/resource/print")
            return r[0] if r else {}
        except Exception:
            return {}

    def get_services(self) -> List[Dict[str, str]]:
        try:
            return self.command("/ip/service/print")
        except Exception:
            return []

    def get_secrets(self) -> List[Dict[str, str]]:
        try:
            return self.command("/ppp/secret/print")
        except Exception:
            return []

    def get_active(self) -> List[Dict[str, str]]:
        try:
            return self.command("/ppp/active/print")
        except Exception:
            return []

    def get_profiles(self) -> List[Dict[str, str]]:
        try:
            return self.command("/ppp/profile/print")
        except Exception:
            return []

    def add_secret(self, name: str, password: str, service: str,
                   profile: str) -> str:
        """Create a PPP secret. Returns the .id of the new entry."""
        self._send_sentence([
            "/ppp/secret/add",
            f"=name={name}",
            f"=password={password}",
            f"=service={service}",
            f"=profile={profile}",
        ])
        while True:
            s = self._read_sentence()
            if s is None:
                raise RuntimeError("No response")
            if s[0] == "!done":
                ret = next((w[5:] for w in s if w.startswith("=ret=")), "")
                return ret
            if s[0] in ("!trap", "!fatal"):
                msg = next(
                    (w.split("=message=", 1)[1] for w in s if "=message=" in w),
                    str(s),
                )
                raise RuntimeError(msg)

    def set_secret(self, sid: str, **attrs: str):
        """Modify an existing PPP secret by .id."""
        words = ["/ppp/secret/set", f"=.id={sid}"]
        for k, v in attrs.items():
            words.append(f"={k}={v}")
        self.command(*words)

    def disable_secret(self, sid: str):
        self.command("/ppp/secret/set", f"=.id={sid}", "=disabled=yes")

    def enable_secret(self, sid: str):
        self.command("/ppp/secret/set", f"=.id={sid}", "=disabled=no")

    def remove_secret(self, sid: str):
        self.command("/ppp/secret/remove", f"=.id={sid}")


# ── Traceroute ──────────────────────────────────────────────────────────────


def run_traceroute(host: str) -> List[Dict]:
    """Run system traceroute and return parsed hops."""
    hops: List[Dict] = []
    try:
        proc = subprocess.run(
            ["traceroute", "-m", "15", "-w", "2", host],
            capture_output=True,
            text=True,
            timeout=45,
        )
        for line in proc.stdout.strip().splitlines()[1:]:
            m = re.match(r"\s*(\d+)\s+(.*)", line)
            if not m:
                continue
            hop_num = int(m.group(1))
            rest = m.group(2)
            ip_match = re.search(r"\(?([\d.]+)\)?", rest)
            times = [float(t) for t in re.findall(r"([\d.]+)\s*ms", rest)]
            hops.append(
                {
                    "hop": hop_num,
                    "host": ip_match.group(1) if ip_match else "* * *",
                    "times": times,
                }
            )
    except FileNotFoundError:
        hops.append({"hop": 0, "host": "traceroute not found", "times": []})
    except subprocess.TimeoutExpired:
        hops.append({"hop": 0, "host": "timed out", "times": []})
    except Exception as e:
        hops.append({"hop": 0, "host": str(e), "times": []})
    return hops


def run_ping_once(host: str, timeout_s: float = 2.0) -> Dict[str, object]:
    """Run a single ICMP ping and return parsed latency."""
    commands = [
        ["ping", "-c", "1", "-W", str(int(timeout_s)), host],  # Linux
        ["ping", "-c", "1", "-t", str(int(timeout_s)), host],  # macOS/BSD fallback
    ]
    last_out = ""
    for cmd in commands:
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=max(3, int(timeout_s) + 2),
            )
            out = (proc.stdout or "") + "\n" + (proc.stderr or "")
            last_out = out
            m = re.search(r"time[=<]\s*([\d.]+)\s*ms", out)
            if m:
                return {"ok": True, "latency_ms": float(m.group(1))}
        except FileNotFoundError:
            return {"ok": False, "error": "ping not found"}
        except subprocess.TimeoutExpired:
            return {"ok": False, "error": "ping timeout"}
        except Exception as e:
            return {"ok": False, "error": str(e)}
    return {"ok": False, "error": "no reply", "raw": last_out}


# ── Port Scanner ────────────────────────────────────────────────────────────

_PORT_NAMES = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    80: "www",
    443: "www-ssl",
    7272: "winbox",
    8728: "api",
    8729: "api-ssl",
}


def scan_ports(host: str, ports: List[int], timeout: float = 2) -> Dict[int, bool]:
    """Concurrent TCP port scan."""
    results: Dict[int, bool] = {}

    def _probe(port: int):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, port))
            s.close()
            results[port] = True
        except Exception:
            results[port] = False

    threads = [threading.Thread(target=_probe, args=(p,)) for p in ports]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=timeout + 1)
    return results


# ── Helpers ─────────────────────────────────────────────────────────────────


def _load_color(pct: float) -> str:
    if pct < 50:
        return "green"
    return "yellow" if pct < 80 else "red"


def _latency_color(ms: float) -> str:
    if ms < 20:
        return "green"
    return "yellow" if ms < 100 else "red"


# ── Focusable Static widget ────────────────────────────────────────────────


class Panel(Static):
    """Static widget that can receive focus (for keyboard navigation)."""

    can_focus = True


# ── TUI Application ────────────────────────────────────────────────────────


class MikroTikMonitor(App):
    """Interactive MikroTik router monitoring dashboard."""

    TITLE = "MikroTik Monitor"

    CSS = """
    Screen {
        background: $surface;
    }

    #dashboard {
        height: 1fr;
        padding: 0 1;
    }

    #top-row {
        height: 14;
        margin-bottom: 1;
    }

    #conn-panel {
        width: 1fr;
        border: tall $success;
        border-title-color: $success;
        border-title-style: bold;
        padding: 0 1;
        margin-right: 1;
    }
    #conn-panel.disconnected {
        border: tall $error;
        border-title-color: $error;
    }
    #conn-panel:focus {
        border: double $success;
    }
    #conn-panel.disconnected:focus {
        border: double $error;
    }

    #svc-table {
        width: 1fr;
        border: tall $primary;
        border-title-color: $primary;
        border-title-style: bold;
    }
    #svc-table:focus {
        border: double $primary;
    }

    #trace-panel {
        height: 12;
        border: tall $warning;
        border-title-color: $warning;
        border-title-style: bold;
        padding: 0 1;
        margin-bottom: 1;
    }
    #trace-panel:focus {
        border: double $warning;
    }

    #bottom-row {
        height: 1fr;
    }

    #secrets-table {
        width: 1fr;
        border: tall $secondary;
        border-title-color: $secondary;
        border-title-style: bold;
        margin-right: 1;
    }
    #secrets-table:focus {
        border: double $secondary;
    }

    #active-table {
        width: 1fr;
        border: tall $accent;
        border-title-color: $accent;
        border-title-style: bold;
    }
    #active-table:focus {
        border: double $accent;
    }

    #debug-view {
        display: none;
        height: 1fr;
        padding: 1;
    }

    #debug-panel {
        border: tall $error;
        border-title-color: $error;
        border-title-style: bold;
        padding: 1 2;
        height: 1fr;
    }

    #apitest-view {
        display: none;
        height: 1fr;
        padding: 1;
    }

    #apitest-panel {
        border: tall $success;
        border-title-color: $success;
        border-title-style: bold;
        padding: 1 2;
        height: 1fr;
    }
    #apitest-panel.running {
        border: tall $warning;
        border-title-color: $warning;
    }
    #apitest-panel.failed {
        border: tall $error;
        border-title-color: $error;
    }

    #rawdata-view {
        display: none;
        height: 1fr;
        padding: 1;
    }

    #rawdata-panel {
        border: tall $primary;
        border-title-color: $primary;
        border-title-style: bold;
        padding: 1 2;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("r", "refresh", "Refresh"),
        Binding("d", "toggle_debug", "Debug"),
        Binding("1", "focus_panel('conn')", "Info", show=True),
        Binding("2", "focus_panel('svc')", "Services", show=True),
        Binding("3", "focus_panel('trace')", "Trace", show=True),
        Binding("4", "focus_panel('secrets')", "Secrets", show=True),
        Binding("5", "focus_panel('active')", "Active", show=True),
        Binding("6", "run_api_test", "API Test", show=True),
        Binding("7", "show_raw_data", "Raw Log", show=True),
    ]

    def __init__(self, host: str, port: int, user: str, password: str):
        super().__init__()
        self.api_host = host
        self.api_port = port
        self.api_user = user
        self.api_password = password
        self.api: Optional[MikroTikAPI] = None
        self._connected = False
        self._identity = ""
        self._login_msg = ""
        self._resource: Dict[str, str] = {}
        self._services: List[Dict[str, str]] = []
        self._secrets: List[Dict[str, str]] = []
        self._active: List[Dict[str, str]] = []
        self._traceroute: List[Dict] = []
        self._ping_history: List[Optional[float]] = []
        self._ping_last_error = ""
        self._port_scan: Dict[int, bool] = {}
        self._errors: List[str] = []
        self._apitest_running = False
        self._apitest_steps: List[Dict] = []

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical(id="dashboard"):
            with Horizontal(id="top-row"):
                yield Panel("[dim]Connecting…[/]", id="conn-panel")
                yield DataTable(id="svc-table")
            yield Panel("[dim]Waiting for traceroute…[/]", id="trace-panel")
            with Horizontal(id="bottom-row"):
                yield DataTable(id="secrets-table")
                yield DataTable(id="active-table")
        with Vertical(id="debug-view"):
            yield Panel("", id="debug-panel")
        with Vertical(id="apitest-view"):
            yield Panel("", id="apitest-panel")
        with VerticalScroll(id="rawdata-view"):
            yield Panel("", id="rawdata-panel")
        yield Footer()

    def on_mount(self):
        self.sub_title = f"{self.api_host}:{self.api_port}"

        self.query_one("#conn-panel").border_title = "Connection"
        self.query_one("#svc-table").border_title = "Services"
        self.query_one("#trace-panel").border_title = "Traceroute"
        self.query_one("#secrets-table").border_title = "PPP Secrets"
        self.query_one("#active-table").border_title = "Active Connections"
        self.query_one("#debug-panel").border_title = "Diagnostics"
        self.query_one("#apitest-panel").border_title = "API Test \u2014 PPP Secret CRUD"
        self.query_one("#rawdata-panel").border_title = "Raw API Log"

        svc = self.query_one("#svc-table", DataTable)
        svc.add_columns("Service", "Port", "Status")
        svc.cursor_type = "row"

        sec = self.query_one("#secrets-table", DataTable)
        sec.add_columns("Name", "Service", "Profile", "Status")
        sec.cursor_type = "row"

        act = self.query_one("#active-table", DataTable)
        act.add_columns("Name", "Service", "Address", "Uptime", "Caller-ID")
        act.cursor_type = "row"

        self._do_connect()
        self._do_traceroute()
        self._do_ping()
        self.set_interval(15, self._auto_refresh)
        self.set_interval(2, self._tick_ping)

    @work(thread=True, exclusive=True, group="api")
    def _do_connect(self):
        try:
            api = MikroTikAPI(self.api_host, self.api_port, timeout=10)
            api.connect()
            ok, msg = api.login(self.api_user, self.api_password)
            self._login_msg = msg
            if not ok:
                self._errors = [f"Login failed: {msg}"]
                self.call_from_thread(self._show_debug)
                return
            self.api = api
            self._connected = True
            self._identity = api.get_identity()
            self._resource = api.get_resource()
            self._services = api.get_services()
            self._secrets = api.get_secrets()
            self._active = api.get_active()
            self.call_from_thread(self._render_dashboard)
        except Exception as exc:
            self._errors = [str(exc)]
            self.call_from_thread(self._show_debug)

    @work(thread=True, exclusive=True, group="trace")
    def _do_traceroute(self):
        self._traceroute = run_traceroute(self.api_host)
        if self._connected:
            self.call_from_thread(self._render_traceroute)
        else:
            self.call_from_thread(self._render_debug_content)

    @work(thread=True, exclusive=True, group="ping")
    def _do_ping(self):
        result = run_ping_once(self.api_host, timeout_s=2.0)
        if result.get("ok"):
            self._ping_history.append(float(result["latency_ms"]))
            self._ping_last_error = ""
        else:
            self._ping_history.append(None)
            self._ping_last_error = str(result.get("error", "no reply"))
        if len(self._ping_history) > 40:
            self._ping_history = self._ping_history[-40:]
        self.call_from_thread(self._render_traceroute)

    @work(thread=True, exclusive=True, group="scan")
    def _do_port_scan(self):
        ports = sorted({self.api_port, 8728, 8729, 80, 443, 22, 23, 21, 7272})
        self._port_scan = scan_ports(self.api_host, ports)
        self.call_from_thread(self._render_debug_content)

    @work(thread=True, exclusive=True, group="api")
    def _do_refresh(self):
        if not self.api or not self.api.logged_in:
            return
        try:
            self._resource = self.api.get_resource()
            self._services = self.api.get_services()
            self._secrets = self.api.get_secrets()
            self._active = self.api.get_active()
            self.call_from_thread(self._render_dashboard)
        except Exception as exc:
            self._connected = False
            self._errors = [f"Connection lost: {exc}"]
            self.call_from_thread(self._show_debug)

    def _auto_refresh(self):
        if self._connected:
            self._do_refresh()

    def _tick_ping(self):
        self._do_ping()

    def _render_dashboard(self):
        self._hide_all_views()
        self.query_one("#dashboard").display = True
        self.sub_title = f"{self._identity}  |  {self.api_host}:{self.api_port}"
        self._render_conn_info()
        self._render_services()
        self._render_traceroute()
        self._render_secrets()
        self._render_active()

    def _render_conn_info(self):
        r = self._resource
        uptime = r.get("uptime", "-")
        version = r.get("version", "-")
        cpu_s = r.get("cpu-load", "0")
        board = r.get("board-name", "-")
        arch = r.get("architecture-name", "")
        total = int(r.get("total-memory", 0))
        free = int(r.get("free-memory", 0))
        used = total - free
        mem_pct = (used / total * 100) if total else 0
        cpu_pct = int(cpu_s) if cpu_s.isdigit() else 0
        latency = self.api.latency_ms if self.api else 0

        W = 20
        cpu_filled = min(int(W * cpu_pct / 100), W)
        mem_filled = min(int(W * mem_pct / 100), W)
        cpu_bar = "\u2588" * cpu_filled + "\u2591" * (W - cpu_filled)
        mem_bar = "\u2588" * mem_filled + "\u2591" * (W - mem_filled)
        cc = _load_color(cpu_pct)
        mc = _load_color(mem_pct)

        total_mb = total / 1048576
        used_mb = used / 1048576

        text = (
            f"[bold green]\u25cf Connected[/]  [dim]({self._login_msg})[/]\n"
            f"\n"
            f"  [bold]Identity :[/]  {self._identity}\n"
            f"  [bold]Host     :[/]  {self.api_host}:{self.api_port}\n"
            f"  [bold]User     :[/]  {self.api_user}\n"
            f"  [bold]Board    :[/]  {board}  {arch}\n"
            f"  [bold]RouterOS :[/]  v{version}\n"
            f"  [bold]Uptime   :[/]  {uptime}\n"
            f"  [bold]CPU      :[/]  [{cc}]{cpu_bar}[/] {cpu_pct}%\n"
            f"  [bold]Memory   :[/]  [{mc}]{mem_bar}[/] {mem_pct:.0f}%"
            f" ({used_mb:.0f}/{total_mb:.0f} MB)\n"
            f"  [bold]Latency  :[/]  {latency:.1f} ms"
        )
        panel = self.query_one("#conn-panel", Panel)
        panel.update(text)
        panel.remove_class("disconnected")

    def _render_services(self):
        tbl = self.query_one("#svc-table", DataTable)
        tbl.clear()
        for s in self._services:
            name = s.get("name", "?")
            port = s.get("port", "?")
            disabled = s.get("disabled", "false") == "true"
            status = (
                Text("\u25cb disabled", style="bright_red")
                if disabled
                else Text("\u25cf enabled", style="green")
            )
            tbl.add_row(name, str(port), status)
        tbl.border_subtitle = f"{len(self._services)} services"

    def _render_traceroute(self):
        lines = []
        hist = self._ping_history[-40:]
        ok_samples = [v for v in hist if v is not None]
        if hist:
            loss = (len(hist) - len(ok_samples)) / len(hist) * 100.0
        else:
            loss = 0.0

        if ok_samples:
            last = ok_samples[-1]
            avg = sum(ok_samples) / len(ok_samples)
            mn = min(ok_samples)
            mx = max(ok_samples)
            lc = _latency_color(last)
            squares = "".join(
                "[green]■[/]" if v is not None else "[red]■[/]" for v in hist
            )
            lines.append(
                f"  [bold]Ping[/]  [{lc}]● {last:.1f} ms[/]  "
                f"[dim](avg {avg:.1f} / min {mn:.1f} / max {mx:.1f}, loss {loss:.0f}%)[/]"
            )
            lines.append(f"        {squares}")
        else:
            msg = self._ping_last_error or "waiting..."
            lines.append(f"  [bold]Ping[/]  [yellow]no reply[/]  [dim]({msg})[/]")

        lines.append("")
        lines.append("  [bold]Traceroute[/]")
        if self._traceroute:
            max_t = max(
                (max(h["times"], default=0) for h in self._traceroute), default=1
            ) or 1
            for h in self._traceroute:
                n, host, times = h["hop"], h["host"], h["times"]
                if times:
                    avg = sum(times) / len(times)
                    w = 25
                    filled = min(int(w * avg / max_t), w)
                    c = _latency_color(avg)
                    blk = "\u2588" * filled + "\u2591" * (w - filled)
                    bar = f"[{c}]{blk}[/]"
                    lines.append(
                        f"  [bold]{n:>2}[/]  {host:<20} {bar}  {avg:.1f} ms"
                    )
                else:
                    lines.append(f"  [bold]{n:>2}[/]  {host:<20} [dim]* * *[/]")
        else:
            lines.append("  [dim]Waiting for traceroute...[/]")
        self.query_one("#trace-panel", Panel).update("\n".join(lines))
        self.query_one("#trace-panel").border_subtitle = (
            f"{len(self._traceroute)} hops | ping 2s"
        )

    def _render_secrets(self):
        tbl = self.query_one("#secrets-table", DataTable)
        tbl.clear()
        for s in self._secrets:
            name = s.get("name", "?")
            svc = s.get("service", "any")
            prof = s.get("profile", "default")
            disabled = s.get("disabled", "false") == "true"
            st = (
                Text("disabled", style="bright_red")
                if disabled
                else Text("enabled", style="green")
            )
            tbl.add_row(name, svc, prof, st)
        tbl.border_subtitle = f"{len(self._secrets)} entries"

    def _render_active(self):
        tbl = self.query_one("#active-table", DataTable)
        tbl.clear()
        for c in self._active:
            tbl.add_row(
                c.get("name", "?"),
                c.get("service", "?"),
                c.get("address", "-"),
                c.get("uptime", "-"),
                c.get("caller-id", "-"),
            )
        tbl.border_subtitle = f"{len(self._active)} online"

    def _show_debug(self):
        self._hide_all_views()
        self.query_one("#debug-view").display = True
        self.query_one("#conn-panel").add_class("disconnected")
        self.sub_title = f"DISCONNECTED  |  {self.api_host}:{self.api_port}"
        self._render_debug_content()
        self._do_port_scan()

    def _render_debug_content(self):
        S = "\u2501"
        L = [
            "[bold red]\u2717 Connection Failed[/]\n",
            f"  [bold]Host :[/]  {self.api_host}",
            f"  [bold]Port :[/]  {self.api_port}",
            f"  [bold]User :[/]  {self.api_user}\n",
        ]
        for e in self._errors:
            L.append(f"  [yellow]\u25ba {e}[/]")

        if self._port_scan:
            L.append(f"\n[bold cyan]{S * 3} Port Scan {S * 38}[/]")
            for port in sorted(self._port_scan):
                name = _PORT_NAMES.get(port, f"port-{port}")
                if port == self.api_port and port not in _PORT_NAMES:
                    name = "api (configured)"
                ok = self._port_scan[port]
                dot = "[green]\u25cf  open[/]" if ok else "[red]\u25cb  closed[/]"
                L.append(f"    {name:<16} {port:>5}   {dot}")
        else:
            L.append("\n  [dim]Scanning ports\u2026[/]")

        if self._traceroute:
            L.append(f"\n[bold cyan]{S * 3} Traceroute {S * 37}[/]")
            for h in self._traceroute:
                n, host, times = h["hop"], h["host"], h["times"]
                avg = f"{sum(times) / len(times):.1f} ms" if times else "* * *"
                L.append(f"    {n:>2}  {host:<20}  {avg}")
        else:
            L.append("  [dim]Running traceroute\u2026[/]")

        L.append(f"\n[bold yellow]{S * 3} Suggestions {S * 36}[/]")
        if self._port_scan:
            api_open = self._port_scan.get(self.api_port, False)
            if not api_open:
                L.append(
                    f"    [red]\u2717[/] Port {self.api_port} is "
                    f"[bold]closed[/] \u2014 check firewall / MikroTik IP > Services"
                )
                alt = [p for p in (8728, 8729) if self._port_scan.get(p)]
                if alt:
                    L.append(f"    [green]\u2192[/] Try port [bold]{alt[0]}[/] instead")
            else:
                L.append(f"    [green]\u2713[/] Port {self.api_port} is [bold]open[/]")
                L.append("    [yellow]?[/] Verify username and password")
                L.append(
                    "    [yellow]?[/] Check API service "
                    "'Available From' address restrictions"
                )

        L.append(
            f"\n  [dim]Press [bold]r[/bold] to retry  |  "
            f"[bold]q[/bold] to quit[/]"
        )
        self.query_one("#debug-panel", Panel).update("\n".join(L))

    def action_refresh(self):
        atv = self.query_one("#apitest-view")
        rv = self.query_one("#rawdata-view")
        if rv.display:
            self._hide_all_views()
            self.query_one("#dashboard").display = True
            self.notify("Back to dashboard")
            return
        if atv.display and not self._apitest_running:
            self._hide_all_views()
            self.query_one("#dashboard").display = True
            self.notify("Back to dashboard")
            self._do_refresh()
            return
        if self._connected:
            self.notify("Refreshing\u2026")
            self._do_refresh()
        else:
            self._errors.clear()
            self._port_scan.clear()
            self._traceroute.clear()
            self.notify("Retrying connection\u2026")
            self._do_connect()
            self._do_traceroute()

    def action_toggle_debug(self):
        dv = self.query_one("#debug-view")
        if dv.display:
            self._hide_all_views()
            self.query_one("#dashboard").display = True
        else:
            self._hide_all_views()
            dv.display = True
            self._render_debug_content()

    def action_run_api_test(self):
        if not self._connected:
            self.notify("Not connected \u2014 connect first", severity="error")
            return
        if self._apitest_running:
            self.notify("Test already running\u2026", severity="warning")
            return
        self._hide_all_views()
        self.query_one("#apitest-view").display = True
        p = self.query_one("#apitest-panel", Panel)
        p.add_class("running")
        p.remove_class("failed")
        self._apitest_steps = []
        self._render_apitest()
        self._do_api_test()

    def _add_test_step(self, label: str, status: str, detail: str = ""):
        self._apitest_steps.append({
            "label": label, "status": status, "detail": detail,
            "ts": time.strftime("%H:%M:%S"),
        })

    def _render_apitest(self):
        S = "\u2501"
        ICONS = {
            "pending": "[dim]\u25cb[/]",
            "running": "[yellow]\u25d4[/]",
            "ok":      "[green]\u2714[/]",
            "fail":    "[red]\u2718[/]",
        }
        lines = [
            f"[bold cyan]{S * 3} PPP Secret CRUD Test {S * 30}[/]\n",
        ]
        for step in self._apitest_steps:
            icon = ICONS.get(step["status"], "?")
            ts = f"[dim]{step['ts']}[/]  "
            line = f"  {ts}{icon}  {step['label']}"
            if step["detail"]:
                line += f"  [dim]\u2014 {step['detail']}[/]"
            lines.append(line)

        if self._apitest_running:
            lines.append(f"\n  [dim yellow]Test in progress\u2026[/]")
        elif self._apitest_steps:
            all_ok = all(s["status"] == "ok" for s in self._apitest_steps)
            if all_ok:
                lines.append(f"\n  [bold green]\u2714 All steps passed![/]")
            else:
                lines.append(f"\n  [bold red]\u2718 Test finished with errors[/]")
            lines.append(
                f"\n  [dim]Press [bold]6[/bold] to run again  |  "
                f"[bold]r[/bold] to go back  |  [bold]q[/bold] to quit[/]"
            )

        self.query_one("#apitest-panel", Panel).update("\n".join(lines))

    @work(thread=True, exclusive=True, group="apitest")
    def _do_api_test(self):
        self._apitest_running = True
        api = self.api
        rand_id = random.randint(1000, 9999)
        username = f"yetfix{rand_id}"
        password = "".join(random.choices(string.ascii_letters + string.digits, k=12))
        new_password = "".join(random.choices(string.ascii_letters + string.digits, k=12))
        sid = None

        SKIP_PROFILES = {"default", "default-encryption"}
        try:
            profile_rows = api.get_profiles()
        except Exception:
            profile_rows = []
        profile_names = [r.get("name", "") for r in profile_rows if r.get("name")]
        user_profiles = [p for p in profile_names if p not in SKIP_PROFILES]
        profile = user_profiles[0] if user_profiles else (
            profile_names[0] if profile_names else "default"
        )

        steps = [
            ("Fetch available profiles", "fetch_profiles"),
            ("Create PPP secret", "create"),
            ("Verify secret exists", "verify_create"),
            ("Change password", "change_pw"),
            ("Verify password changed", "verify_pw"),
            ("Disable secret", "disable"),
            ("Verify disabled", "verify_disable"),
            ("Re-enable secret", "enable"),
            ("Verify re-enabled", "verify_enable"),
            ("Delete secret", "delete"),
            ("Verify deleted", "verify_delete"),
        ]

        for label, _ in steps:
            self._add_test_step(label, "pending")
        self.call_from_thread(self._render_apitest)

        def run_step(idx, action_fn):
            self._apitest_steps[idx]["status"] = "running"
            self._apitest_steps[idx]["ts"] = time.strftime("%H:%M:%S")
            self.call_from_thread(self._render_apitest)
            time.sleep(0.6)
            try:
                detail = action_fn()
                self._apitest_steps[idx]["status"] = "ok"
                self._apitest_steps[idx]["detail"] = detail or ""
            except Exception as e:
                self._apitest_steps[idx]["status"] = "fail"
                self._apitest_steps[idx]["detail"] = str(e)
                self.call_from_thread(self._render_apitest)
                raise
            self._apitest_steps[idx]["ts"] = time.strftime("%H:%M:%S")
            self.call_from_thread(self._render_apitest)

        try:
            def do_fetch_profiles():
                all_names = ", ".join(profile_names[:8])
                return f"found {len(profile_names)} [{all_names}] \u2192 using \"{profile}\""
            run_step(0, do_fetch_profiles)

            def do_create():
                nonlocal sid
                sid = api.add_secret(username, password, "pppoe", profile)
                return f"{username} / {password}  (profile={profile}, id={sid})"
            run_step(1, do_create)

            def do_verify_create():
                secrets = api.get_secrets()
                found = any(s.get("name") == username for s in secrets)
                if not found:
                    raise RuntimeError(f"{username} not found in secrets list")
                return f"{username} found in {len(secrets)} secrets"
            run_step(2, do_verify_create)

            def do_change_pw():
                api.set_secret(sid, password=new_password)
                return f"password changed to {new_password}"
            run_step(3, do_change_pw)

            def do_verify_pw():
                secrets = api.get_secrets()
                entry = next((s for s in secrets if s.get("name") == username), None)
                if not entry:
                    raise RuntimeError("secret not found after password change")
                return f"{username} still present"
            run_step(4, do_verify_pw)

            def do_disable():
                api.disable_secret(sid)
                return f"{username} disabled"
            run_step(5, do_disable)

            def do_verify_disable():
                secrets = api.get_secrets()
                entry = next((s for s in secrets if s.get("name") == username), None)
                if not entry:
                    raise RuntimeError("secret not found")
                if entry.get("disabled") != "true":
                    raise RuntimeError("disabled flag is not true")
                return "disabled=true confirmed"
            run_step(6, do_verify_disable)

            def do_enable():
                api.enable_secret(sid)
                return f"{username} re-enabled"
            run_step(7, do_enable)

            def do_verify_enable():
                secrets = api.get_secrets()
                entry = next((s for s in secrets if s.get("name") == username), None)
                if not entry:
                    raise RuntimeError("secret not found")
                if entry.get("disabled") == "true":
                    raise RuntimeError("still disabled")
                return "disabled=false confirmed"
            run_step(8, do_verify_enable)

            def do_delete():
                api.remove_secret(sid)
                return f"{username} removed"
            run_step(9, do_delete)

            def do_verify_delete():
                secrets = api.get_secrets()
                found = any(s.get("name") == username for s in secrets)
                if found:
                    raise RuntimeError(f"{username} still exists!")
                return f"confirmed gone ({len(secrets)} secrets remain)"
            run_step(10, do_verify_delete)

        except Exception:
            pass
        finally:
            self._apitest_running = False
            p = self.query_one("#apitest-panel", Panel)
            p.remove_class("running")
            all_ok = all(s["status"] == "ok" for s in self._apitest_steps)
            if not all_ok:
                p.add_class("failed")
            self.call_from_thread(self._render_apitest)
            self.call_from_thread(self._do_refresh)

    def _hide_all_views(self):
        self.query_one("#dashboard").display = False
        self.query_one("#debug-view").display = False
        self.query_one("#apitest-view").display = False
        self.query_one("#rawdata-view").display = False

    def action_show_raw_data(self):
        rv = self.query_one("#rawdata-view")
        if rv.display:
            rv.display = False
            self.query_one("#dashboard").display = True
            return
        self._hide_all_views()
        rv.display = True
        self._render_raw_data()

    def _render_raw_data(self):
        S = "\u2501"
        log = self.api.raw_log if self.api else []
        if not log:
            self.query_one("#rawdata-panel", Panel).update(
                "[dim]No API commands recorded yet.[/]"
            )
            return

        lines = [
            f"[bold cyan]{S * 3} Raw API Log "
            f"({len(log)} entries) {S * 33}[/]\n",
        ]
        MAX_CHARS = 1000
        for i, entry in enumerate(log):
            ts = entry["ts"]
            cmd = entry["cmd"]
            ms = entry["elapsed_ms"]
            rows = entry["rows"]
            err = entry["error"]
            info = entry.get("info", "")

            if err:
                icon = "[red]\u2718[/]"
                summary = f"[red]ERROR: {err}[/]"
            elif info:
                icon = "[green]\u2714[/]"
                summary = f"[green]{info}[/]"
            else:
                icon = "[green]\u2714[/]"
                summary = f"[green]{rows} row(s)[/]"

            idx = f"[dim]#{i+1:<3}[/]"
            lines.append(
                f"  {idx} [dim]{ts}[/]  {icon}  [bold]{cmd}[/]"
                f"  {summary}  [dim]{ms}ms[/]"
            )

            chars_used = 0
            truncated = False
            for sentence in entry["sentences"]:
                if truncated:
                    break
                tag = sentence[0] if sentence else "?"
                rest = sentence[1:] if len(sentence) > 1 else []
                if tag == "!re":
                    attrs = []
                    for w in rest:
                        if w.startswith("="):
                            attrs.append(w[1:])
                    for attr in attrs:
                        chars_used += len(attr) + 20
                        if chars_used > MAX_CHARS:
                            lines.append(
                                f"             [dim yellow]\u2026 truncated "
                                f"(>{MAX_CHARS} chars)[/]"
                            )
                            truncated = True
                            break
                        lines.append(f"             [dim cyan]!re[/]  {attr}")
                elif tag == "!done":
                    extra = ""
                    for w in rest:
                        if w.startswith("=ret="):
                            extra = f"  ret={w[5:]}"
                    lines.append(f"             [dim green]!done{extra}[/]")
                elif tag in ("!trap", "!fatal"):
                    lines.append(
                        f"             [red]{tag}[/]  {' '.join(rest)}"
                    )
                else:
                    lines.append(
                        f"             [dim]{' '.join(sentence)}[/]"
                    )
                    chars_used += sum(len(w) for w in sentence) + 20

            if not entry["sentences"]:
                if info:
                    lines.append(f"             [dim]{info}[/]")

            lines.append("")

        lines.append(
            f"  [dim]Press [bold]7[/bold] to close  |  "
            f"[bold]r[/bold] to refresh data  |  "
            f"[bold]q[/bold] to quit  |  "
            f"scroll with [bold]\u2191\u2193[/bold] or mouse[/]"
        )
        self.query_one("#rawdata-panel", Panel).update("\n".join(lines))

    def action_focus_panel(self, panel: str):
        targets = {
            "conn": "#conn-panel",
            "svc": "#svc-table",
            "trace": "#trace-panel",
            "secrets": "#secrets-table",
            "active": "#active-table",
        }
        t = targets.get(panel)
        if t:
            try:
                self.query_one(t).focus()
            except Exception:
                pass


def main():
    if len(sys.argv) != 5:
        print(f"Usage: {sys.argv[0]} <ip> <port> <username> <password>")
        sys.exit(1)

    app = MikroTikMonitor(
        host=sys.argv[1],
        port=int(sys.argv[2]),
        user=sys.argv[3],
        password=sys.argv[4],
    )
    app.run()


if __name__ == "__main__":
    main()
PYTHON_SCRIPT

if [ -t 0 ]; then
    "$PYTHON" "$_TMPPY" "$@"
elif ( exec < /dev/tty ) 2>/dev/null; then
    "$PYTHON" "$_TMPPY" "$@" < /dev/tty
else
    "$PYTHON" "$_TMPPY" "$@"
fi
