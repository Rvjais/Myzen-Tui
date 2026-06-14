#!/usr/bin/env python3
import configparser, json, sqlite3, urllib.request, urllib.parse, urllib.error
import subprocess, re, shlex, sys, os, base64, asyncio, shutil
import ctypes, ctypes.util
from datetime import datetime, timezone, timedelta
from pathlib import Path

from textual.app import App, ComposeResult, ScreenStackError
from textual.screen import Screen
from textual.widgets import Static, Input, Button, LoadingIndicator
from textual.containers import Container, Horizontal
from textual import work

CONFIG = Path.home() / ".config" / "ai.zs" / "zs.ini"
DB = Path.home() / ".local" / "share" / "ai.zs" / "zs" / "zs.db"
REPORT_DB = Path.home() / ".local" / "share" / "ai.zs" / "report_cache.json"
TOKEN_FILE = Path.home() / ".config" / "ai.zs" / ".tui_token.json"
TRACKING_DIR = Path.home() / ".local" / "share" / "applications"
AUTH = "https://auth.in.we360.ai"
GATEWAY = "https://api.in.we360.ai"
REALM = "ind-prod"
API_TIMEOUT = 10
CLIENT = None
TOKEN = None
RT = None
IDLE_WARN = 1200
AUTO_PUNCH_TIMEOUT = 300

XSSInfo = None
_XSS_AVAIL = False
_XSS_LIB = None
_X11_LIB = None
_X11_DISP = None

def _init_xss():
    global _XSS_AVAIL, _XSS_LIB, _X11_LIB, _X11_DISP, XSSInfo
    try:
        xss_path = ctypes.util.find_library("Xss")
        x11_path = ctypes.util.find_library("X11")
        if not xss_path or not x11_path:
            return
        _XSS_LIB = ctypes.cdll.LoadLibrary(xss_path)
        _X11_LIB = ctypes.cdll.LoadLibrary(x11_path)
        _X11_LIB.XOpenDisplay.restype = ctypes.c_void_p
        _X11_LIB.XOpenDisplay.argtypes = [ctypes.c_char_p]
        _X11_DISP = _X11_LIB.XOpenDisplay(None)
        if not _X11_DISP:
            return
        _X11_LIB.XDefaultRootWindow.argtypes = [ctypes.c_void_p]
        _X11_LIB.XDefaultRootWindow.restype = ctypes.c_ulong
        # probe whether XScreenSaver is actually available
        class XScreenSaverInfo(ctypes.Structure):
            _fields_ = [
                ("window", ctypes.c_ulong),
                ("state", ctypes.c_int),
                ("kind", ctypes.c_int),
                ("since", ctypes.c_ulong),
                ("idle", ctypes.c_ulong),
                ("event_mask", ctypes.c_ulong),
            ]
        XSSInfo = XScreenSaverInfo
        _XSS_LIB.XScreenSaverQueryInfo.argtypes = [
            ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(XScreenSaverInfo),
        ]
        _XSS_LIB.XScreenSaverQueryInfo.restype = ctypes.c_int
        # probe — suppress stderr while calling to avoid
        # "MIT-SCREEN-SAVER missing" diagnostic on non-Xss servers
        import os
        devnull = os.dup(2)
        nullfd = os.open(os.devnull, os.O_WRONLY)
        os.dup2(nullfd, 2)
        root = _X11_LIB.XDefaultRootWindow(_X11_DISP)
        probe = XScreenSaverInfo()
        ok = _XSS_LIB.XScreenSaverQueryInfo(
            _X11_DISP, root, ctypes.byref(probe)
        )
        os.dup2(devnull, 2)
        os.close(nullfd)
        os.close(devnull)
        if not ok:
            return
        _XSS_AVAIL = True
    except Exception:
        pass

_init_xss()

def get_idle_secs():
    if _XSS_AVAIL:
        try:
            root = _X11_LIB.XDefaultRootWindow(_X11_DISP)
            info = XSSInfo()
            _XSS_LIB.XScreenSaverQueryInfo(_X11_DISP, root, ctypes.byref(info))
            return info.idle // 1000
        except Exception:
            pass
    try:
        import dbus
        bus = dbus.SessionBus()
        obj = bus.get_object("org.freedesktop.ScreenSaver", "/ScreenSaver")
        idle = obj.GetSessionIdleTime(dbus_interface="org.freedesktop.ScreenSaver")
        return int(idle) // 1000
    except Exception:
        pass
    try:
        r = subprocess.run(["xprintidle"], capture_output=True, timeout=2)
        if r.returncode == 0 and r.stdout.strip():
            return int(r.stdout.strip()) // 1000
    except Exception:
        pass
    return 0


def load_client():
    global CLIENT
    if CLIENT:
        return
    try:
        c = configparser.ConfigParser()
        c.read(CONFIG)
        CLIENT = c.get("General", "client_id")
    except Exception:
        CLIENT = "wqih-czom-vklz"


def auth(email, password):
    global TOKEN, RT
    load_client()
    data = urllib.parse.urlencode(
        {"client_id": CLIENT, "grant_type": "password", "username": email, "password": password}
    ).encode()
    req = urllib.request.Request(
        f"{AUTH}/realms/{REALM}/protocol/openid-connect/token",
        data=data, headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    try:
        with urllib.request.urlopen(req, timeout=API_TIMEOUT) as r:
            j = json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            desc = json.loads(e.read()).get("error_description", "Login failed")
        except Exception:
            desc = "Login failed"
        raise RuntimeError(desc) from e
    except Exception as e:
        raise RuntimeError(f"Connection failed: {e}") from e
    if "access_token" not in j:
        raise RuntimeError(j.get("error_description", "Login failed"))
    TOKEN = j["access_token"]
    RT = j.get("refresh_token")
    save_tokens()


def refresh():
    global TOKEN, RT
    if not RT:
        return
    try:
        data = urllib.parse.urlencode(
            {"client_id": CLIENT, "grant_type": "refresh_token", "refresh_token": RT}
        ).encode()
        req = urllib.request.Request(
            f"{AUTH}/realms/{REALM}/protocol/openid-connect/token",
            data=data, headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        with urllib.request.urlopen(req, timeout=API_TIMEOUT) as r:
            j = json.loads(r.read())
            TOKEN = j.get("access_token", TOKEN)
            RT = j.get("refresh_token", RT)
    except Exception:
        pass


def api(path, method="GET", body=None):
    if not TOKEN:
        return {}
    h = {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}
    d = json.dumps(body).encode() if body else None
    try:
        req = urllib.request.Request(f"{GATEWAY}{path}", data=d, headers=h, method=method)
        with urllib.request.urlopen(req, timeout=API_TIMEOUT) as r:
            return json.loads(r.read())
    except Exception:
        return {}


def punch_in():
    try:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        r = api("/api/v1/me/punch_in/", "POST", {"time_in": now})
        return bool(r and ("id" in r or r.get("success")))
    except Exception:
        return False


def punch_out():
    try:
        r = api("/api/v1/me/punch_out/", "POST", {})
        return bool(r and ("id" in r or r.get("success")))
    except Exception:
        return False


def break_start():
    try:
        bt = api("/api/v1/me/break_types/")
        if not bt:
            return False
        r = api("/api/v1/me/start_break/", "POST", {"break_type_id": bt[0]["id"]})
        return bool(r and ("id" in r or r.get("success")))
    except Exception:
        return False


def break_end():
    try:
        r = api("/api/v1/me/end_break/", "POST", {})
        return bool(r and ("id" in r or r.get("success")))
    except Exception:
        return False


def fetch_activity():
    if not DB.exists():
        return []
    try:
        conn = sqlite3.connect(str(DB))
        rows = conn.execute(
            "SELECT app_name, start_time, duration FROM app_stat_events ORDER BY start_time DESC LIMIT 3"
        ).fetchall()
        conn.close()
        return rows
    except Exception:
        return []


def fetch_dates():
    if not DB.exists():
        return []
    try:
        conn = sqlite3.connect(str(DB))
        rows = conn.execute(
            "SELECT DISTINCT substr(start_time,1,10) as d FROM app_stat_events ORDER BY d DESC"
        ).fetchall()
        conn.close()
        return [r[0] for r in rows]
    except Exception:
        return []


def date_summary(date_str):
    if not DB.exists():
        return 0, 0, 0
    try:
        conn = sqlite3.connect(str(DB))
        row = conn.execute(
            "SELECT COALESCE(SUM(active_time),0), COALESCE(SUM(duration),0), COUNT(DISTINCT CASE WHEN app_name IS NOT NULL AND app_name != '' AND app_name != 'Zen' THEN app_name END) "
            "FROM app_stat_events WHERE substr(start_time,1,10) = ?", (date_str,)
        ).fetchone()
        conn.close()
        return (int(row[0]), int(row[1]), int(row[2]))
    except Exception:
        return 0, 0, 0


def date_apps(date_str):
    if not DB.exists():
        return []
    try:
        conn = sqlite3.connect(str(DB))
        rows = conn.execute(
            "SELECT app_name, COALESCE(SUM(active_time),0), COALESCE(SUM(duration),0) "
            "FROM app_stat_events WHERE substr(start_time,1,10) = ? "
            "GROUP BY app_name ORDER BY SUM(duration) DESC", (date_str,)
        ).fetchall()
        conn.close()
        return rows
    except Exception:
        return []


def dur_str(secs):
    if secs < 0:
        secs = 0
    h, r = divmod(int(secs), 3600)
    m, s = divmod(r, 60)
    return f"{h:02d}:{m:02d}:{s:02d}"


def fmt_t(iso):
    if not iso:
        return "--:--:--"
    try:
        pt = datetime.fromisoformat(iso.replace("Z", "+00:00").replace("z", "+00:00"))
        return pt.astimezone().strftime("%H:%M:%S")
    except Exception:
        return iso[:19]


def total_secs(logs):
    total = 0.0
    for l in logs:
        time_out = l.get("time_out")
        if not time_out:
            continue
        try:
            tin = datetime.fromisoformat(l["time_in"].replace("Z", "+00:00").replace("z", "+00:00"))
            tout = datetime.fromisoformat(time_out.replace("Z", "+00:00").replace("z", "+00:00"))
            total += (tout - tin).total_seconds()
        except Exception:
            pass
    return total


def load_state():
    refresh()
    s = api("/api/v1/me/status/")
    if not s:
        return [], [], False, False, None, None
    logs = s.get("punch_logs") or []
    ubreaks = s.get("user_breaks") or []
    latest = logs[-1] if logs else {}
    pi = bool(latest and latest.get("time_out") is None)
    ob = bool(len(ubreaks) > 0 and ubreaks[-1].get("break_end_time") is None)
    pi_time = latest.get("time_in") if pi else None
    po_time = latest.get("time_out") if not pi else None
    return logs, ubreaks, pi, ob, pi_time, po_time


def is_configured():
    return CONFIG.exists() and Path("/opt/zs/zs").exists()


def extract_keyconfig(script_path):
    name = Path(script_path).name
    b64 = name.replace(".sh", "")
    try:
        raw = base64.b64decode(b64).decode()
        j = json.loads(raw)
        return {"stealth_key": j["skey"], "tenant_id": j["tid"]}
    except Exception:
        return None


def get_deb_url(script_path):
    try:
        for line in open(script_path):
            m = re.search(r'DEB_INSTALLER_URL="([^"]+)"', line)
            if m:
                return m.group(1)
    except Exception:
        return None


def save_report_cache(records):
    try:
        REPORT_DB.parent.mkdir(parents=True, exist_ok=True)
        REPORT_DB.write_text(json.dumps(records))
    except Exception:
        pass


def load_report_cache():
    try:
        return json.loads(REPORT_DB.read_text())
    except Exception:
        return None


REPORT_COLUMNS = [
    "attendance_date", "punch_in", "punch_out",
    "active_duration", "online_duration", "idle_duration", "break_duration",
    "productive_duration", "unproductive_duration", "neutral_duration",
    "productive_percent", "mouse_clicks", "key_presses",
    "top_application_used", "top_application_duration",
    "top_url_used", "top_url_duration",
]

def fetch_report(start_date, end_date, page=1, limit=0):
    body = {
        "start_date": start_date,
        "end_date": end_date,
        "mode": "detailed",
        "columns": REPORT_COLUMNS,
        "page": page,
        "limit": limit,
    }
    return api("/query/external/reports/dynamic_report", "POST", body)


TRACKING_SKIP = {"wine-extension", "waydroid", "code-url-handler", "code-insiders-url-handler"}

def _tracking_env(content, fname):
    if "Alacritty" in content:
        return "WINIT_UNIX_BACKEND=x11"
    for line in content.splitlines():
        if line.startswith("Categories="):
            if "Qt" in line or "KDE" in line:
                return "QT_QPA_PLATFORM=xcb"
            break
    return "GDK_BACKEND=x11"

def scan_apps():
    apps = {}
    sys_dir = Path("/usr/share/applications")
    local_dir = TRACKING_DIR
    seen = set()
    for f in sorted(sys_dir.glob("*.desktop")):
        try:
            if any(x in f.name for x in TRACKING_SKIP):
                continue
            txt = f.read_text()
            name = None
            is_app = False
            hidden = False
            for line in txt.splitlines():
                if not name and line.startswith("Name="):
                    name = line.split("=", 1)[1]
                if line.startswith("Type=Application"):
                    is_app = True
                if line.startswith("Hidden=true"):
                    hidden = True
            if not name or not is_app or hidden:
                continue
            seen.add(f.name)
            lf = local_dir / f.name
            env = _tracking_env(txt, f.name)
            tracked = False
            if lf.exists():
                try:
                    with lf.open() as fh:
                        tracked = "env " in fh.read(4096)
                except Exception:
                    pass
            apps[f.name] = {"name": name, "tracked": tracked, "path": f, "local": lf, "env": env}
        except Exception:
            continue
    for f in sorted(local_dir.glob("*.desktop")):
        if f.name in seen:
            continue
        if any(x in f.name for x in TRACKING_SKIP):
            continue
        try:
            txt = f.read_text()
            name = None
            for line in txt.splitlines():
                if line.startswith("Name="):
                    name = line.split("=", 1)[1]
                    break
            if not name:
                continue
            tracked = "env " in txt
            apps[f.name] = {
                "name": name, "tracked": tracked, "path": None, "local": f,
                "env": "GDK_BACKEND=x11",
            }
        except Exception:
            continue
    return apps

def set_tracking(dotdesktop, enable):
    sys_f = Path("/usr/share/applications") / dotdesktop
    local_f = TRACKING_DIR / dotdesktop
    if enable:
        if sys_f.exists():
            txt = sys_f.read_text()
        elif local_f.exists():
            txt = local_f.read_text()
        else:
            return
        if re.search(r"^Exec=env \S+ ", txt, re.MULTILINE):
            return
        env = _tracking_env(txt, dotdesktop)
        txt = re.sub(r"^(Exec=)", lambda m, e=env: f"Exec=env {e} ", txt, flags=re.MULTILINE)
        TRACKING_DIR.mkdir(parents=True, exist_ok=True)
        local_f.write_text(txt)
    else:
        if local_f.exists():
            if sys_f.exists():
                local_f.unlink(missing_ok=True)
            else:
                txt = local_f.read_text()
                txt = re.sub(r"^Exec=env \S+ ", "Exec=", txt, flags=re.MULTILINE)
                local_f.write_text(txt)
    subprocess.run(["update-desktop-database", str(TRACKING_DIR)], capture_output=True)


class SetupScreen(Screen):
    def compose(self):
        yield Container(
            Static("First-Time Setup", id="setup-title"),
            Static("Enter the path to your organisation's .sh setup file\ndownloaded from the WE360 portal.", id="setup-desc"),
            Input(placeholder="/home/user/Downloads/eyJ...==.sh", id="setup-path"),
            Button("Run Setup", variant="primary", id="setup-btn"),
            LoadingIndicator(id="setup-spinner"),
            Static("", id="setup-msg"),
            id="setup-box",
        )

    def on_button_pressed(self, event):
        if event.button.id == "setup-btn":
            path = self.query_one("#setup-path", Input).value.strip()
            if not path or not Path(path).exists():
                self.query_one("#setup-msg", Static).update("File not found.")
                return
            self._btn = self.query_one("#setup-btn", Button)
            self._msg = self.query_one("#setup-msg", Static)
            self._spinner = self.query_one("#setup-spinner", LoadingIndicator)
            self._btn.disabled = True
            self.run_setup(path)

    @work(thread=True)
    def run_setup(self, path):
        def ui(fn, *args, **kwargs):
            return self.app.call_from_thread(fn, *args, **kwargs)
        ui(self._spinner.add_class, "-visible")
        cfg = extract_keyconfig(path)
        if not cfg:
            ui(self._msg.update, "Could not decode keyconfig from filename.")
            ui(self._spinner.remove_class, "-visible")
            ui(setattr, self._btn, "disabled", False)
            return
        if not Path("/opt/zs/zs").exists():
            deb_url = get_deb_url(path)
            if not deb_url:
                ui(self._msg.update, "Could not find download URL in script.")
                ui(self._spinner.remove_class, "-visible")
                ui(setattr, self._btn, "disabled", False)
                return
            ui(self._msg.update, "Downloading agent package...")
            deb_path = "/tmp/zs.deb"
            try:
                urllib.request.urlretrieve(deb_url, deb_path)
            except Exception:
                ui(self._msg.update, "Download failed. Check internet connection.")
                ui(self._spinner.remove_class, "-visible")
                ui(setattr, self._btn, "disabled", False)
                return
            ui(self._msg.update, "Extracting agent...")
            extract_dir = "/tmp/zs_extract"
            subprocess.run(["rm", "-rf", extract_dir], capture_output=True)
            subprocess.run(["mkdir", "-p", extract_dir], capture_output=True)
            try:
                subprocess.run(["dpkg-deb", "-x", deb_path, extract_dir], check=True, capture_output=True)
            except FileNotFoundError:
                try:
                    subprocess.run(["ar", "x", deb_path], check=True, capture_output=True, cwd=extract_dir)
                    for f in sorted(os.listdir(extract_dir)):
                        if f.startswith("data.tar"):
                            subprocess.run(["tar", "xf", os.path.join(extract_dir, f), "-C", extract_dir], check=True)
                            break
                    else:
                        raise RuntimeError("No data.tar found in deb")
                except Exception as e:
                    ui(self._msg.update, f"Extraction failed: {e}")
                    ui(self._spinner.remove_class, "-visible")
                    ui(setattr, self._btn, "disabled", False)
                    return
            ui(self._msg.update, "Installing agent (requires admin password)...")
            try:
                subprocess.run(["pkexec", "mkdir", "-p", "/opt/zs"], check=True)
                subprocess.run(["pkexec", "cp", "-r", f"{extract_dir}/opt/zs/.", "/opt/zs/"], check=True)
            except Exception:
                ui(self._msg.update,
                    "Automatic install failed. Run this manually:\n"
                    "sudo mkdir -p /opt/zs && sudo cp -r /tmp/zs_extract/opt/zs/. /opt/zs/")
                ui(self._spinner.remove_class, "-visible")
                ui(setattr, self._btn, "disabled", False)
                return
        ui(self._msg.update, "Writing organisation config...")
        kc = {"stealth_key": cfg["stealth_key"], "tenant_id": cfg["tenant_id"]}
        tmp_kc = "/tmp/keyconfig.json"
        json.dump(kc, open(tmp_kc, "w"))
        try:
            subprocess.run(["pkexec", "cp", tmp_kc, "/opt/zs/keyconfig.json"], check=True)
        except Exception:
            ui(self._msg.update,
                "Config write failed. Run manually:\n"
                "sudo cp /tmp/keyconfig.json /opt/zs/keyconfig.json")
            ui(self._spinner.remove_class, "-visible")
            ui(setattr, self._btn, "disabled", False)
            return
        ui(self._msg.update, "Starting background service...")
        subprocess.run(["systemctl", "--user", "daemon-reload"], capture_output=True)
        subprocess.run(["systemctl", "--user", "start", "zsvcmonitor"], capture_output=True)
        subprocess.run(["systemctl", "--user", "enable", "zsvcmonitor"], capture_output=True)
        subprocess.run(["systemctl", "--user", "start", "zsconfigure.timer"], capture_output=True)
        subprocess.run(["systemctl", "--user", "enable", "zsconfigure.timer"], capture_output=True)
        ui(self._msg.update, "Setup complete! You can now log in.")
        ui(self._spinner.remove_class, "-visible")
        import time
        time.sleep(1)
        ui(self.app.switch_screen, LoginScreen())


class LoginScreen(Screen):
    def compose(self) -> ComposeResult:
        yield Container(
            Static("WE360 MyZen", id="login-title"),
            Static("Employee Productivity Tracker", id="login-sub"),
            Input(placeholder="Email", id="email"),
            Input(placeholder="Password", password=True, id="password"),
            Button("Login", variant="primary", id="login-btn"),
            Static("", id="login-err"),
            id="login-box",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "login-btn":
            self.do_login()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "email":
            self.query_one("#password", Input).focus()
        elif event.input.id == "password":
            self.do_login()

    def do_login(self) -> None:
        email = self.query_one("#email", Input).value.strip()
        pw = self.query_one("#password", Input).value.strip()
        if not email or not pw:
            self.query_one("#login-err", Static).update("Email and password required.")
            return
        self._err = self.query_one("#login-err", Static)
        self._email = email
        self._pw = pw
        self._err.update("Authenticating...")
        self._do_login()

    @work(thread=True)
    def _do_login(self):
        try:
            auth(self._email, self._pw)
        except RuntimeError as e:
            self.app.call_from_thread(self._err.update, str(e))
            return
        self.app.call_from_thread(self.app.switch_screen, DashboardScreen())


class IdleWarningScreen(Screen):
    def compose(self) -> ComposeResult:
        yield Container(
            Static("\u26a0", id="idle-icon"),
            Static("INACTIVITY WARNING", id="idle-title"),
            Static("", id="idle-msg"),
            Static("", id="idle-countdown"),
            Static("Press any key to dismiss", id="idle-hint"),
            id="idle-box",
        )

    def on_mount(self) -> None:
        self.update_msg()
        self.set_interval(1, self.update_msg)

    def update_msg(self) -> None:
        idle = get_idle_secs()
        elapsed = idle - IDLE_WARN
        remaining = AUTO_PUNCH_TIMEOUT - elapsed
        if remaining <= 0:
            self.dismiss(do_auto=True)
            return
        self.query_one("#idle-msg", Static).update(
            f"You've been idle for {dur_str(idle)}"
        )
        self.query_one("#idle-countdown", Static).update(
            f"Auto punch-out in {dur_str(remaining)}"
        )
        cd = self.query_one("#idle-countdown", Static)
        if remaining <= 60:
            cd.add_class("urgent")
        else:
            cd.remove_class("urgent")

    def dismiss(self, do_auto=False) -> None:
        self.app.pop_screen()
        if do_auto:
            self.app._auto_punch()


class HistoryScreen(Screen):
    def compose(self) -> ComposeResult:
        yield Container(
            Static("WORK HISTORY", id="hist-title"),
            Static("", id="hist-list"),
            Static("", id="hist-divider"),
            Static("", id="hist-detail"),
            Static("", id="hist-keybar"),
            id="hist-main",
        )

    def on_mount(self) -> None:
        self.dates = fetch_dates()
        self.idx = 0
        self.show()

    def show(self) -> None:
        if not self.dates:
            self.query_one("#hist-list", Static).update("  No history yet")
            self.query_one("#hist-detail", Static).update("")
            self.query_one("#hist-keybar", Static).update("  Q:Quit")
            return
        lines = []
        for i, d in enumerate(self.dates):
            mark = "\u25b8" if i == self.idx else " "
            active, total, napps = date_summary(d)
            pct = f"{active * 100 // max(total, 1)}%"
            lines.append(f"  {mark} {d}  {dur_str(active)} active  {pct}  {napps} apps")
        self.query_one("#hist-list", Static).update("\n".join(lines))
        self.show_detail()

    def show_detail(self) -> None:
        if not self.dates:
            return
        d = self.dates[self.idx]
        active, total, napps = date_summary(d)
        apps = date_apps(d)
        lines = []
        lines.append(f"  Date: {d}")
        lines.append(f"  Active: {dur_str(active)}  Total tracked: {dur_str(total)}")
        if total:
            lines.append(f"  Idle: {(total - active) * 100 // total}%")
        lines.append("")
        lines.append(f"  Applications ({napps}):")
        for name, act, dur in apps[:8]:
            label = (name or "(system)")[:20]
            lines.append(f"    {label:<20}  active:{dur_str(act)}  total:{dur_str(dur)}")
        self.query_one("#hist-detail", Static).update("\n".join(lines))
        self.query_one("#hist-keybar", Static).update("  \u2191\u2193:Navigate  Q:Quit  ESC:Back")

    def on_key(self, event):
        if event.key == "escape":
            self.app.pop_screen()
            s = self.app.screen
            if isinstance(s, DashboardScreen):
                s.load_data()
        elif event.key == "q":
            self.app.exit()
        elif event.key in ("up", "k"):
            self.idx = max(0, self.idx - 1)
            self.show()
        elif event.key in ("down", "j"):
            self.idx = min(len(self.dates) - 1, self.idx + 1)
            self.show()
        event.stop()


class ReportsScreen(Screen):
    def compose(self) -> ComposeResult:
        yield Container(
            Static("DYNAMIC REPORT", id="report-title"),
            Static("", id="report-range"),
            Static("", id="report-list"),
            Static("", id="report-divider"),
            Static("", id="report-detail"),
            Static("", id="report-keybar"),
            id="report-main",
        )

    def on_mount(self) -> None:
        self.records = []
        self.idx = 0
        self.query_one("#report-list", Static).update("  Loading report data...")
        self.query_one("#report-keybar", Static).update("  Fetching from WE360...")
        self._load_data()

    @work(thread=True)
    def _load_data(self):
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=7)
        r = fetch_report(
            start.strftime("%Y-%m-%dT00:00:00"),
            end.strftime("%Y-%m-%dT23:59:59"),
        )
        raw = r.get("data") if r else None
        if raw:
            save_report_cache(r)
        else:
            cached = load_report_cache()
            raw = cached.get("data") if cached else None
        records = {}
        for d in (raw or []):
            date = d.get("attendance_date")
            if date:
                records[date] = d
        self.app.call_from_thread(self._set_results, records)

    def _set_results(self, records):
        self.records = sorted(records.items(), key=lambda x: x[0], reverse=True)
        self.show()

    def show(self) -> None:
        if not self.records:
            self.query_one("#report-list", Static).update("  No data available")
            self.query_one("#report-detail", Static).update("")
            self.query_one("#report-keybar", Static).update("  Q:Quit  ESC:Back")
            self.query_one("#report-range", Static).update("")
            return
        now = datetime.now(timezone.utc)
        week_ago = now - timedelta(days=7)
        self.query_one("#report-range", Static).update(
            f"  {week_ago.strftime('%b %d')} \u2013 {now.strftime('%b %d, %Y')}"
        )
        lines = []
        for i, (date, rec) in enumerate(self.records):
            mark = "\u25b8" if i == self.idx else " "
            active = rec.get("active_duration", "--:--:--")
            prod = rec.get("productive_percent")
            pct = f"{prod:.0f}%" if isinstance(prod, (int, float)) else "--"
            lines.append(f"  {mark} {date}  {active} active  {pct}")
        self.query_one("#report-list", Static).update("\n".join(lines))
        self.show_detail()

    def show_detail(self) -> None:
        if not self.records:
            return
        date, rec = self.records[self.idx]
        def v(key, default="--"):
            val = rec.get(key)
            if val is None or val == "-":
                return default
            return val
        lines = []
        lines.append(f"  Date: {date}")
        lines.append("")
        lines.append(f"  Punch in:   {v('punch_in')}      Punch out:  {v('punch_out')}")
        lines.append(f"  Active:     {v('active_duration')}    Idle:       {v('idle_duration')}")
        lines.append(f"  Online:     {v('online_duration')}    Break:      {v('break_duration')}")
        prod_pct = v("productive_percent")
        prod_str = f"({prod_pct}%)" if prod_pct != "--" else ""
        lines.append(f"  Productive: {v('productive_duration')}  {prod_str}")
        lines.append(f"  Unproduct:  {v('unproductive_duration')}")
        lines.append(f"  Keys:       {v('key_presses')}           Clicks:     {v('mouse_clicks')}")
        top_app = v("top_application_used")
        top_app_dur = v("top_application_duration")
        if top_app and top_app != "--":
            lines.append(f"  Top app:    {top_app[:24]}  ({top_app_dur})")
        top_url = v("top_url_used")
        top_url_dur = v("top_url_duration")
        if top_url and top_url != "--":
            lines.append(f"  Top URL:    {top_url[:24]}  ({top_url_dur})")
        self.query_one("#report-detail", Static).update("\n".join(lines))
        self.query_one("#report-keybar", Static).update(
            "  \u2191\u2193:Navigate  ESC:Back  Q:Quit"
        )

    def on_key(self, event):
        if event.key == "escape":
            self.app.pop_screen()
            s = self.app.screen
            if isinstance(s, DashboardScreen):
                s.load_data()
        elif event.key == "q":
            self.app.exit()
        elif event.key in ("up", "k"):
            self.idx = max(0, self.idx - 1)
            self.show()
        elif event.key in ("down", "j"):
            self.idx = min(len(self.records) - 1, self.idx + 1)
            self.show()
        event.stop()


class TrackingScreen(Screen):
    def compose(self) -> ComposeResult:
        yield Container(
            Static("APPS TRACKED BY AGENT", id="track-title"),
            Container(Static("", id="track-list"), id="track-scroll"),
            Static("", id="track-keybar"),
            id="track-main",
        )

    def on_mount(self) -> None:
        self.idx = 0
        self.items = sorted(scan_apps().items(), key=lambda x: x[1]["name"].lower())
        self.show()

    def show(self) -> None:
        total = len(self.items)
        start = max(0, self.idx - 10)
        end = min(total, start + 21)
        lines = []
        for i in range(start, end):
            _, a = self.items[i]
            mark = "\u25b8" if i == self.idx else " "
            box = "[x]" if a["tracked"] else "[ ]"
            lines.append(f"  {mark} {box}  {a['name']}")
        self.query_one("#track-list", Static).update("\n".join(lines))
        self.query_one("#track-keybar", Static).update(
            f"  \u2191\u2193:Navigate  SPACE:Toggle  ESC:Back  Q:Quit  ({self.idx + 1}/{total})"
        )

    def on_key(self, event):
        if event.key == "escape":
            self.app.pop_screen()
        elif event.key == "q":
            self.app.exit()
        elif event.key in ("up", "k"):
            self.idx = max(0, self.idx - 1)
            self.show()
        elif event.key in ("down", "j"):
            self.idx = min(len(self.items) - 1, self.idx + 1)
            self.show()
        elif event.key in (" ", "space", "enter"):
            desk, a = self.items[self.idx]
            enable = not a["tracked"]
            set_tracking(desk, enable)
            a["tracked"] = enable
            self.show()
            self.app.notify(
                f"{'Tracked' if enable else 'Untracked'}: {a['name']}"
            )
        event.stop()


class DashboardScreen(Screen):
    def compose(self) -> ComposeResult:
        yield Container(
            Static("WE360 MyZen Live", id="dash-title"),
            Static("...", id="status-bar"),
            Horizontal(
                Container(
                    Static("PUNCH", classes="stat-head"),
                    Static("--:--:--", id="punch-val", classes="stat-val"),
                    Static("", id="punch-sub", classes="stat-sub"),
                    classes="stat-box",
                ),
                Container(
                    Static("BREAK", classes="stat-head"),
                    Static("--", id="break-val", classes="stat-val"),
                    classes="stat-box",
                ),
                Container(
                    Static("TODAY", classes="stat-head"),
                    Static("--:--:--", id="today-val", classes="stat-val"),
                    classes="stat-box",
                ),
                id="stats-row",
            ),
            Static("RECENT ACTIVITY", id="section-title"),
            Static("No activity yet", id="activity-box"),
            Static("", id="keybar"),
            id="main",
        )

    def on_mount(self) -> None:
        self.logs = []
        self.ubreaks = []
        self.pi = False
        self.ob = False
        self.pi_time = None
        self.po_time = None
        self.load_data()
        self.set_interval(1, self.tick)
        self.set_interval(60, self.load_data)
        self.update_keybar()

    def update_keybar(self) -> None:
        parts = []
        if not self.pi:
            parts.append("P:IN")
        if self.pi:
            parts.append("O:OUT")
        if not self.ob:
            parts.append("B:BREAK")
        if self.ob:
            parts.append("E:END")
        parts.append("R:RFSH")
        parts.append("V:RPRT")
        parts.append("H:HIST")
        parts.append("T:TRK")
        parts.append("Q:QUIT")
        self.query_one("#keybar", Static).update("  ".join(parts))

    def load_data(self) -> None:
        self.logs, self.ubreaks, self.pi, self.ob, self.pi_time, self.po_time = load_state()
        self.update_ui()
        self.update_keybar()

    def update_ui(self) -> None:
        pi = self.pi
        ob = self.ob
        now = datetime.now(timezone.utc)
        logs = self.logs
        ubreaks = self.ubreaks
        pi_time = self.pi_time
        po_time = self.po_time

        bar = self.query_one("#status-bar", Static)
        if pi:
            bar.remove_class("out").add_class("in")
            bar.update("  \u25cf PUNCHED IN  ")
        else:
            bar.remove_class("in").add_class("out")
            bar.update("  \u25cb PUNCHED OUT  ")

        ttl = total_secs(logs)
        if pi and pi_time:
            try:
                pt = datetime.fromisoformat(pi_time.replace("Z", "+00:00").replace("z", "+00:00"))
                ttl += (now - pt).total_seconds()
            except Exception:
                pass
        self.query_one("#today-val", Static).update(dur_str(ttl))

        break_val = "--"
        if ob:
            if len(ubreaks) > 0:
                break_val = ubreaks[-1].get("break_type_name", "Break")[:10]
        self.query_one("#break-val", Static).update(break_val)

        timer_val = "--:--:--"
        since_val = ""
        if pi and pi_time:
            try:
                pt = datetime.fromisoformat(pi_time.replace("Z", "+00:00").replace("z", "+00:00"))
                d = (now - pt).total_seconds()
                timer_val = dur_str(d)
                since_val = f"since {fmt_t(pi_time)}"
            except Exception:
                pass
        elif not pi and po_time:
            since_val = f"out since {fmt_t(po_time)}"

        self.query_one("#punch-val", Static).update(timer_val)
        self.query_one("#punch-sub", Static).update(since_val)

        acts = fetch_activity()
        act_box = self.query_one("#activity-box", Static)
        if acts:
            lines = []
            for r in acts[:3]:
                name = (r[0] or "?")[:28]
                ds = str(int(r[2] or 0)) + "s"
                lines.append(f"{name:<28}  {ds:>6}")
            act_box.update("\n".join(lines))
        else:
            act_box.update("No activity yet")

    def tick(self) -> None:
        if not self.pi or not self.pi_time:
            return
        try:
            now = datetime.now(timezone.utc)
            pt = datetime.fromisoformat(self.pi_time.replace("Z", "+00:00").replace("z", "+00:00"))
            d = (now - pt).total_seconds()
            self.query_one("#punch-val", Static).update(dur_str(d))
            ttl = total_secs(self.logs) + d
            self.query_one("#today-val", Static).update(dur_str(ttl))
        except Exception:
            pass


def save_tokens():
    try:
        TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
        TOKEN_FILE.write_text(json.dumps({"access_token": TOKEN, "refresh_token": RT}))
    except Exception:
        pass


def try_restore_session():
    global TOKEN, RT
    try:
        data = json.loads(TOKEN_FILE.read_text())
        TOKEN = data.get("access_token")
        RT = data.get("refresh_token")
        if TOKEN:
            refresh()
            if TOKEN:
                s = api("/api/v1/me/status/")
                if s:
                    return True
    except Exception:
        pass
    TOKEN = None
    RT = None
    return False


class MyZenApp(App):
    CSS = """
    Screen {
        background: #1a1b26;
    }

    LoginScreen {
        align: center middle;
    }

    #login-box {
        width: 50;
        height: auto;
        border: thick #7aa2f7;
        padding: 1 2;
        background: #24283b;
    }

    #login-title {
        text-align: center;
        text-style: bold;
        color: #7aa2f7;
        height: 3;
        padding: 1 0;
    }

    #login-sub {
        text-align: center;
        color: #565f89;
        height: 1;
        margin-bottom: 1;
    }

    Input {
        margin: 0 0 1 0;
    }

    Button {
        margin: 1 0;
    }

    #login-err {
        color: #f7768e;
        text-align: center;
        height: 1;
    }

    DashboardScreen {
        overflow: auto;
    }

    #main {
        margin: 0 1;
        height: auto;
        layout: vertical;
    }

    #dash-title {
        text-style: bold;
        color: #7aa2f7;
        height: 3;
        text-align: center;
        padding: 1 0;
    }

    #status-bar {
        height: 3;
        text-align: center;
        text-style: bold;
        margin: 0 0 1 0;
        padding: 1 0;
        color: #c0caf5;
    }

    #status-bar.in {
        background: #1a3a1a;
        color: #9ece6a;
    }

    #status-bar.out {
        background: #3a1515;
        color: #f7768e;
    }

    #stats-row {
        height: auto;
        margin: 0 0 1 0;
    }

    .stat-box {
        width: 1fr;
        border: solid #3b4261;
        margin: 0 1 0 0;
        background: #24283b;
        min-width: 14;
    }

    .stat-box:last-child {
        margin: 0 0 0 0;
    }

    .stat-head {
        text-style: bold;
        color: #565f89;
        height: 1;
        text-align: center;
        margin-top: 1;
    }

    .stat-val {
        text-style: bold;
        color: #7dcfff;
        height: 3;
        text-align: center;
        padding: 1 0 0 0;
    }

    .stat-sub {
        color: #565f89;
        height: 1;
        text-align: center;
        margin-bottom: 1;
    }

    #section-title {
        text-style: bold;
        color: #565f89;
        height: 1;
        margin: 0 0 0 0;
    }

    #activity-box {
        color: #c0caf5;
        height: auto;
        min-height: 1;
        margin: 0 0 1 0;
        border: solid #3b4261;
        padding: 0 1;
        background: #24283b;
    }

    #keybar {
        dock: bottom;
        height: 1;
        text-align: center;
        color: #565f89;
        background: #1f2335;
    }

    IdleWarningScreen {
        align: center middle;
    }

    #idle-box {
        width: 44;
        height: auto;
        border: thick #e0af68;
        padding: 1 2;
        background: #24283b;
    }

    #idle-icon {
        text-align: center;
        color: #e0af68;
        height: 3;
        padding: 1 0;
    }

    #idle-title {
        text-align: center;
        text-style: bold;
        color: #e0af68;
        height: 1;
    }

    #idle-msg {
        text-align: center;
        color: #c0caf5;
        height: 1;
        margin-top: 1;
    }

    #idle-countdown {
        text-align: center;
        color: #f7768e;
        height: 1;
        text-style: bold;
        margin-top: 1;
    }

    #idle-countdown.urgent {
        color: #f7768e;
        text-style: bold;
        background: #3a1515;
    }

    #idle-hint {
        text-align: center;
        color: #565f89;
        height: 1;
        margin-top: 1;
    }

    HistoryScreen {
        overflow: auto;
    }

    #hist-main {
        margin: 0 1;
        height: auto;
    }

    #hist-title {
        text-style: bold;
        color: #7aa2f7;
        height: 3;
        text-align: center;
        padding: 1 0;
    }

    #hist-list {
        color: #c0caf5;
        height: auto;
        min-height: 1;
        margin: 0 0 0 0;
        background: #24283b;
        border: solid #3b4261;
        padding: 0 1;
    }

    #hist-divider {
        height: 1;
    }

    #hist-detail {
        color: #c0caf5;
        height: auto;
        min-height: 1;
        margin: 0 0 0 0;
        background: #24283b;
        border: solid #3b4261;
        padding: 0 1;
    }

    #hist-keybar {
        dock: bottom;
        height: 1;
        text-align: center;
        color: #565f89;
        background: #1f2335;
    }

    ReportsScreen {
        overflow: auto;
    }

    #report-main {
        margin: 0 1;
        height: auto;
    }

    #report-title {
        text-style: bold;
        color: #7aa2f7;
        height: 3;
        text-align: center;
        padding: 1 0;
    }

    #report-range {
        color: #565f89;
        height: 1;
        margin: 0 0 0 0;
    }

    #report-list {
        color: #c0caf5;
        height: auto;
        min-height: 1;
        margin: 0 0 0 0;
        background: #24283b;
        border: solid #3b4261;
        padding: 0 1;
    }

    #report-divider {
        height: 1;
    }

    #report-detail {
        color: #c0caf5;
        height: auto;
        min-height: 1;
        margin: 0 0 0 0;
        background: #24283b;
        border: solid #3b4261;
        padding: 0 1;
    }

    #report-keybar {
        dock: bottom;
        height: 1;
        text-align: center;
        color: #565f89;
        background: #1f2335;
    }

    #track-main {
        height: 100%;
    }
    #track-title {
        height: 3;
        text-align: center;
        text-style: bold;
        color: #7aa2f7;
        padding: 1 0;
    }
    #track-scroll {
        height: 1fr;
        overflow-y: auto;
        margin: 0 1;
    }
    #track-list {
        color: #c0caf5;
        height: auto;
        min-height: 1;
    }
    #track-keybar {
        dock: bottom;
        height: 1;
        text-align: center;
        color: #565f89;
        background: #1f2335;
    }

    #setup-spinner {
        margin: 1 0;
        display: none;
    }
    #setup-spinner.-visible {
        display: block;
    }
    #setup-msg {
        height: 3;
        text-align: center;
        color: #a9b1d6;
    }
    """

    def _ui(self, fn, *args, **kwargs):
        return self.call_from_thread(fn, *args, **kwargs)

    def _on_key(self, event):
        s = self.screen
        if isinstance(s, HistoryScreen):
            return
        if isinstance(s, IdleWarningScreen):
            s.dismiss()
            event.stop()
            return
        if not isinstance(s, DashboardScreen):
            return
        handled = True
        if event.key == "p" and not s.pi:
            self.notify("Processing...")
            self._punch(s)
        elif event.key == "o" and s.pi:
            self.notify("Processing...")
            self._unpunch(s)
        elif event.key == "b" and not s.ob:
            self.notify("Processing...")
            self._break_start(s)
        elif event.key == "e" and s.ob:
            self.notify("Processing...")
            self._break_end(s)
        elif event.key == "r":
            self.notify("Processing...")
            self._refresh(s)
        elif event.key == "h":
            self.notify("Processing...")
            self.push_screen(HistoryScreen())
        elif event.key == "v":
            self.notify("Processing...")
            self.push_screen(ReportsScreen())
        elif event.key == "t":
            self.push_screen(TrackingScreen())
        elif event.key == "q":
            self.exit()
        else:
            handled = False
        if handled:
            event.stop()

    @work(thread=True)
    def _punch(self, s):
        if punch_in():
            self._ui(s.load_data)
            self._ui(self.notify, "Punched in")
        else:
            self._ui(self.notify, "Punch-in failed", severity="error")

    @work(thread=True)
    def _unpunch(self, s):
        if punch_out():
            self._ui(s.load_data)
            self._ui(self.notify, "Punched out")
        else:
            self._ui(self.notify, "Punch-out failed", severity="error")

    @work(thread=True)
    def _break_start(self, s):
        if break_start():
            self._ui(s.load_data)
            self._ui(self.notify, "Break started")
        else:
            self._ui(self.notify, "Break start failed", severity="error")

    @work(thread=True)
    def _break_end(self, s):
        if break_end():
            self._ui(s.load_data)
            self._ui(self.notify, "Break ended")
        else:
            self._ui(self.notify, "Break end failed", severity="error")

    @work(thread=True)
    def _refresh(self, s):
        self._ui(s.load_data)
        self._ui(self.notify, "Refreshed")

    def check_idle(self) -> None:
        try:
            s = self.screen
        except ScreenStackError:
            return
        if isinstance(s, IdleWarningScreen):
            return
        if not isinstance(s, DashboardScreen):
            return
        if not getattr(s, 'pi', None):
            return
        idle = get_idle_secs()
        if idle > IDLE_WARN + AUTO_PUNCH_TIMEOUT:
            self._auto_punch()
        elif idle > IDLE_WARN:
            self.push_screen(IdleWarningScreen())

    def _auto_punch(self):
        if getattr(self, '_auto_punching', False):
            return
        self._auto_punching = True
        self._do_auto_punch()

    @work(thread=True)
    def _do_auto_punch(self):
        try:
            ok = punch_out()
            if ok:
                self._ui(self.notify, "Auto punched out due to inactivity", severity="warning")
                s = self.screen
                if isinstance(s, DashboardScreen):
                    self._ui(s.load_data)
            else:
                self._ui(self.notify, "Auto punch-out failed", severity="error")
            self._ui(sys.stdout.write, "\a")
            self._ui(sys.stdout.flush)
        finally:
            self._ui(setattr, self, "_auto_punching", False)

    def on_mount(self) -> None:
        if try_restore_session():
            self.push_screen(DashboardScreen())
        elif is_configured():
            self.push_screen(LoginScreen())
        else:
            self.push_screen(SetupScreen())
        self.set_interval(5, self.check_idle)


def main():
    app = MyZenApp()
    app.run()


if __name__ == "__main__":
    main()
