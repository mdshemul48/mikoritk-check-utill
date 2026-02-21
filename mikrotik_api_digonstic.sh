#!/usr/bin/env python3
"""MikroTik TUI Monitor — comprehensive router monitoring dashboard."""

# ── Auto-install dependencies ───────────────────────────────────────────────
import subprocess as _sp
import sys as _sys
import os as _os


def _ensure_deps():
    try:
        import textual  # noqa: F401
    except ImportError:
        print("\033[33m⚡ Installing dependencies (first run only)…\033[0m")
        _sp.check_call(
            [_sys.executable, "-m", "pip", "install", "textual"],
            stdout=_sp.PIPE,
            stderr=_sp.PIPE,
        )
        print("\033[32m✓ Dependencies installed. Restarting…\033[0m")
        _os.execv(_sys.executable, [_sys.executable] + _sys.argv)


_ensure_deps()

# ── Imports ─────────────────────────────────────────────────────────────────
import binascii
import hashlib
import re
import socket
import struct
import threading
import time
from typing import Dict, List, Optional, Tuple

from rich.text import Text
from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
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

    # ── connection ──────────────────────────────────────────────────────────

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        t0 = time.monotonic()
        self.sock.connect((self.host, self.port))
        self.latency_ms = (time.monotonic() - t0) * 1000
        self.connected = True

    def disconnect(self):
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
        self.connected = False
        self.logged_in = False

    # ── wire helpers ────────────────────────────────────────────────────────

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

    # ── authentication ──────────────────────────────────────────────────────

    def login(self, user: str, password: str) -> Tuple[bool, str]:
        """Authenticate — auto-detects old (challenge) vs new (plaintext) style."""
        self._send_sentence(["/login", f"=name={user}", f"=password={password}"])
        resp = self._read_sentence()
        if resp is None:
            return False, "No response (timeout)"

        if resp[0] == "!done" and not any(w.startswith("=ret=") for w in resp):
            self.logged_in = True
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
            if r2 and r2[0] == "!done":
                self.logged_in = True
                return True, "challenge-response"
            return False, f"Challenge rejected: {r2}"

        if resp[0] in ("!trap", "!fatal"):
            msg = next(
                (w.split("=message=", 1)[1] for w in resp if "=message=" in w),
                str(resp),
            )
            return False, msg

        return False, f"Unexpected: {resp}"

    # ── command execution ───────────────────────────────────────────────────

    def command(self, *words: str) -> List[Dict[str, str]]:
        """Send API command; return list of attribute dicts (one per !re)."""
        self._send_sentence(list(words))
        rows: List[Dict[str, str]] = []
        while True:
            sentence = self._read_sentence()
            if sentence is None:
                break
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
                raise RuntimeError(attrs.get("message", str(sentence)))
        return rows

    # ── high-level fetchers ─────────────────────────────────────────────────

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


# ── Traceroute ──────────────────────────────────────────────────────────────


def run_traceroute(host: str) -> List[Dict]:
    """Run system traceroute and return parsed hops."""
    hops: List[Dict] = []
    try:
        proc = _sp.run(
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
    except _sp.TimeoutExpired:
        hops.append({"hop": 0, "host": "timed out", "times": []})
    except Exception as e:
        hops.append({"hop": 0, "host": str(e), "times": []})
    return hops


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


def _bar(value: float, maximum: float, width: int = 20) -> Tuple[str, str]:
    """Return (bar_string, color)."""
    ratio = min(value / maximum, 1.0) if maximum else 0
    filled = int(width * ratio)
    color = _load_color(ratio * 100)
    return "█" * filled + "░" * (width - filled), color


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

    /* ── dashboard layout ─────────────────────────────────── */

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

    /* ── debug view ───────────────────────────────────────── */

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
        self._port_scan: Dict[int, bool] = {}
        self._errors: List[str] = []

    # ── compose ─────────────────────────────────────────────────────────────

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
        yield Footer()

    # ── mount ───────────────────────────────────────────────────────────────

    def on_mount(self):
        self.sub_title = f"{self.api_host}:{self.api_port}"

        self.query_one("#conn-panel").border_title = "Connection"
        self.query_one("#svc-table").border_title = "Services"
        self.query_one("#trace-panel").border_title = "Traceroute"
        self.query_one("#secrets-table").border_title = "PPP Secrets"
        self.query_one("#active-table").border_title = "Active Connections"
        self.query_one("#debug-panel").border_title = "Diagnostics"

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
        self.set_interval(15, self._auto_refresh)

    # ── workers (background threads) ────────────────────────────────────────

    @work(thread=True, exclusive=True, group="api")
    def _do_connect(self):
        """Connect, login, fetch everything."""
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

    @work(thread=True, exclusive=True, group="scan")
    def _do_port_scan(self):
        ports = sorted({self.api_port, 8728, 8729, 80, 443, 22, 23, 21, 7272})
        self._port_scan = scan_ports(self.api_host, ports)
        self.call_from_thread(self._render_debug_content)

    @work(thread=True, exclusive=True, group="api")
    def _do_refresh(self):
        """Re-fetch data on existing connection."""
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

    # ── dashboard rendering ─────────────────────────────────────────────────

    def _render_dashboard(self):
        self.query_one("#dashboard").display = True
        self.query_one("#debug-view").display = False
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
        cpu_bar = "█" * cpu_filled + "░" * (W - cpu_filled)
        mem_bar = "█" * mem_filled + "░" * (W - mem_filled)
        cc = _load_color(cpu_pct)
        mc = _load_color(mem_pct)

        total_mb = total / 1048576
        used_mb = used / 1048576

        text = (
            f"[bold green]● Connected[/]  [dim]({self._login_msg})[/]\n"
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
                Text("○ disabled", style="bright_red")
                if disabled
                else Text("● enabled", style="green")
            )
            tbl.add_row(name, str(port), status)
        tbl.border_subtitle = f"{len(self._services)} services"

    def _render_traceroute(self):
        if not self._traceroute:
            return
        max_t = max(
            (max(h["times"], default=0) for h in self._traceroute), default=1
        ) or 1
        lines = []
        for h in self._traceroute:
            n, host, times = h["hop"], h["host"], h["times"]
            if times:
                avg = sum(times) / len(times)
                w = 25
                filled = min(int(w * avg / max_t), w)
                c = _latency_color(avg)
                bar = f"[{c}]{'█' * filled}{'░' * (w - filled)}[/]"
                lines.append(
                    f"  [bold]{n:>2}[/]  {host:<20} {bar}  {avg:.1f} ms"
                )
            else:
                lines.append(f"  [bold]{n:>2}[/]  {host:<20} [dim]* * *[/]")
        self.query_one("#trace-panel", Panel).update("\n".join(lines))
        self.query_one("#trace-panel").border_subtitle = f"{len(self._traceroute)} hops"

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

    # ── debug / failure view ────────────────────────────────────────────────

    def _show_debug(self):
        self.query_one("#dashboard").display = False
        self.query_one("#debug-view").display = True
        self.query_one("#conn-panel").add_class("disconnected")
        self.sub_title = f"DISCONNECTED  |  {self.api_host}:{self.api_port}"
        self._render_debug_content()
        self._do_port_scan()

    def _render_debug_content(self):
        S = "━"
        L = [
            "[bold red]✗ Connection Failed[/]\n",
            f"  [bold]Host :[/]  {self.api_host}",
            f"  [bold]Port :[/]  {self.api_port}",
            f"  [bold]User :[/]  {self.api_user}\n",
        ]
        for e in self._errors:
            L.append(f"  [yellow]► {e}[/]")

        # port scan results
        if self._port_scan:
            L.append(f"\n[bold cyan]{S * 3} Port Scan {S * 38}[/]")
            for port in sorted(self._port_scan):
                name = _PORT_NAMES.get(port, f"port-{port}")
                if port == self.api_port and port not in _PORT_NAMES:
                    name = "api (configured)"
                ok = self._port_scan[port]
                dot = "[green]●  open[/]" if ok else "[red]○  closed[/]"
                L.append(f"    {name:<16} {port:>5}   {dot}")
        else:
            L.append("\n  [dim]Scanning ports…[/]")

        # traceroute results
        if self._traceroute:
            L.append(f"\n[bold cyan]{S * 3} Traceroute {S * 37}[/]")
            for h in self._traceroute:
                n, host, times = h["hop"], h["host"], h["times"]
                avg = f"{sum(times) / len(times):.1f} ms" if times else "* * *"
                L.append(f"    {n:>2}  {host:<20}  {avg}")
        else:
            L.append("  [dim]Running traceroute…[/]")

        # suggestions
        L.append(f"\n[bold yellow]{S * 3} Suggestions {S * 36}[/]")
        if self._port_scan:
            api_open = self._port_scan.get(self.api_port, False)
            if not api_open:
                L.append(
                    f"    [red]✗[/] Port {self.api_port} is "
                    f"[bold]closed[/] — check firewall / MikroTik IP > Services"
                )
                alt = [p for p in (8728, 8729) if self._port_scan.get(p)]
                if alt:
                    L.append(f"    [green]→[/] Try port [bold]{alt[0]}[/] instead")
            else:
                L.append(f"    [green]✓[/] Port {self.api_port} is [bold]open[/]")
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

    # ── actions ─────────────────────────────────────────────────────────────

    def action_refresh(self):
        if self._connected:
            self.notify("Refreshing…")
            self._do_refresh()
        else:
            self._errors.clear()
            self._port_scan.clear()
            self._traceroute.clear()
            self.notify("Retrying connection…")
            self._do_connect()
            self._do_traceroute()

    def action_toggle_debug(self):
        dv = self.query_one("#debug-view")
        db = self.query_one("#dashboard")
        if dv.display:
            dv.display = False
            db.display = True
        else:
            db.display = False
            dv.display = True
            self._render_debug_content()

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


# ── Entry point ─────────────────────────────────────────────────────────────


def main():
    if len(_sys.argv) != 5:
        print(f"Usage: {_sys.argv[0]} <ip> <port> <username> <password>")
        _sys.exit(1)

    app = MikroTikMonitor(
        host=_sys.argv[1],
        port=int(_sys.argv[2]),
        user=_sys.argv[3],
        password=_sys.argv[4],
    )
    app.run()


if __name__ == "__main__":
    main()
