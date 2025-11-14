# LFTUN — v5.7.2 (compat DNS)
# - Правим падение: убраны geoip-правила; DNS — в «legacy» формате (строки), чтобы не было ошибки
#   "unknown transport type: http" на старых/нестандартных сборках sing-box.
# - Остальное как в v5.7.x: автосборка runtime, RU-direct через domain_suffix, 1x IP-check и т.д.
#
# GUI НЕ ТРОГАЕМ.

import os, sys, re, json, time, threading, queue, subprocess, shutil, atexit, hashlib, base64, warnings
from pathlib import Path
from urllib.parse import urlparse, parse_qs, unquote

import tkinter as tk
from tkinter import scrolledtext as tkst
from tkinter import filedialog, simpledialog, messagebox

import ttkbootstrap as tb
from ttkbootstrap.constants import *
from PIL import Image, ImageTk
import requests

# ---------------- Admin ----------------
def ensure_admin_and_relaunch(title="Нужны права администратора"):
    if os.name != "nt":
        return True
    try:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return True
    if is_admin:
        return True
    try:
        from ttkbootstrap.dialogs import Messagebox
        ok = Messagebox.yesno(title, "Для поднятия TUN-интерфейса нужны права администратора. Перезапустить приложение с правами администратора?")
        if not ok:
            return False
        if getattr(sys, "frozen", False):
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, "", None, 1)
        else:
            script = Path(__file__).resolve()
            args = " ".join([f'"{str(script)}"'] + [f'"{a}"' for a in sys.argv[1:]])
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, args, None, 1)
        os._exit(0)
    except Exception:
        return False

# ---------------- Paths ----------------
BASE = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
EXE_DIR = Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else Path(__file__).resolve().parent
ASSETS = BASE / "assets"
PROFILES_DIR = EXE_DIR / "_profiles"
ACTIVE_FILE = PROFILES_DIR / "active.txt"

def _find_asset(*names):
    pools = [ASSETS, EXE_DIR / "assets", EXE_DIR / "_internal" / "assets", Path.cwd() / "assets"]
    low = [n.lower() for n in names]
    for root in pools:
        if not root.exists(): continue
        for p in root.iterdir():
            if p.is_file() and p.name.lower() in low: return p
    return None

def _logo(size=96):
    p = _find_asset("lf.png","LF.png")
    if not p:
        img = Image.new("RGBA", (size, size), (0,0,0,0)); return ImageTk.PhotoImage(img)
    return ImageTk.PhotoImage(Image.open(p).convert("RGBA").resize((size, size), Image.LANCZOS))

# ---------------- sing-box ----------------
def find_singbox() -> Path | None:
    candidates = [
        EXE_DIR/"_internal"/"bin"/"sing-box.exe", EXE_DIR/"_internal"/"bin"/"sing-box",
        BASE/"_internal"/"bin"/"sing-box.exe", BASE/"_internal"/"bin"/"sing-box",
        EXE_DIR/"sing-box.exe", EXE_DIR/"sing-box",
        BASE/"sing-box.exe", BASE/"sing-box",
        Path.cwd()/"sing-box.exe", Path.cwd()/"sing-box",
    ]
    for p in candidates:
        if p.exists(): return p
    try:
        found = list(EXE_DIR.rglob("sing-box.exe")) + list(EXE_DIR.rglob("sing-box"))
        if found: return found[0]
    except Exception: pass
    return None

SINGBOX_BIN = find_singbox()

def get_tun_alias_from_config(cfg: Path, default="LFTUN") -> str:
    try:
        data = json.loads(cfg.read_text(encoding="utf-8", errors="ignore"))
        for ib in data.get("inbounds", []):
            if ib.get("type") == "tun":
                return ib.get("interface_name", default)
    except Exception:
        pass
    return default

def _cfg_fp(p: Path) -> str:
    try: return hashlib.sha1(p.read_bytes()).hexdigest()[:10]
    except Exception: return "na"

def _cfg_hint(p: Path) -> str:
    try:
        data = json.loads(p.read_text(encoding="utf-8", errors="ignore"))
        outs = data.get("outbounds", [])
        if outs:
            o = outs[0]
            addr = o.get("server") or o.get("server_address") or ""
            sni = (o.get("tls") or {}).get("server_name") or o.get("server_name") or ""
            if addr or sni: return f"server={addr or '-'} sni={sni or '-'}"
    except Exception: pass
    return ""

def find_default_config() -> Path | None:
    for p in [
        EXE_DIR / "config" / "config.json",
        BASE / "config" / "config.json",
        EXE_DIR / "_internal" / "config" / "config.json",
        BASE / "_internal" / "config" / "config.json",
    ]:
        if p.exists(): return p
    return None

DEFAULT_CONFIG_PATH = find_default_config()

# ---------------- Profiles ----------------
def _profile_dir(name: str) -> Path: return PROFILES_DIR / name
def _profile_cfg(name: str) -> Path: return _profile_dir(name) / "config.json"
def _profile_runtime(name: str) -> Path: return _profile_dir(name) / "runtime" / "config.json"
def _profile_sub(name: str) -> Path: return _profile_dir(name) / "subscription.txt"
def _profile_log(name: str) -> Path: return _profile_dir(name) / "singbox.log"
def _profile_exc_file(name: str) -> Path: return _profile_dir(name) / "exclusions.json"

def _list_profiles():
    if not PROFILES_DIR.exists(): return []
    return [p.name for p in PROFILES_DIR.iterdir() if p.is_dir()]

def _read_active_name() -> str | None:
    try: return ACTIVE_FILE.read_text(encoding="utf-8").strip() or None
    except Exception: return None

def _write_active_name(name: str):
    PROFILES_DIR.mkdir(parents=True, exist_ok=True)
    ACTIVE_FILE.write_text(name, encoding="utf-8")

def _effective_cfg_for(name: str | None) -> Path | None:
    if not name: return None
    rt = _profile_runtime(name)
    if rt.exists(): return rt
    base = _profile_cfg(name)
    return base if base.exists() else None

# ---------------- VLESS helpers ----------------
import base64
def _maybe_b64(s: str) -> str:
    try:
        s = s.strip()
        pad = (-len(s)) % 4
        s2 = s + ("=" * pad)
        return base64.b64decode(s2.encode("ascii"), validate=False).decode("utf-8", errors="ignore")
    except Exception:
        return ""

def _extract_first_uri_from_text(txt: str) -> str | None:
    m = re.search(r"(vless://[^\s]+)", txt, re.IGNORECASE)
    if m: return m.group(1).strip()
    decoded = _maybe_b64(txt)
    if decoded:
        m2 = re.search(r"(vless://[^\s]+)", decoded, re.IGNORECASE)
        if m2: return m2.group(1).strip()
    for token in re.findall(r"[A-Za-z0-9+/=_\\-]{24,}", txt):
        dec = _maybe_b64(token)
        if not dec: continue
        m3 = re.search(r"(vless://[^\s]+)", dec, re.IGNORECASE)
        if m3: return m3.group(1).strip()
    return None

from urllib.parse import urlparse, parse_qs, unquote
def _parse_vless(uri: str) -> dict:
    u = urlparse(uri)
    uuid = unquote(u.username or "")
    host = u.hostname or ""
    port = int(u.port or 443)
    q = {k.lower(): v for k, v in parse_qs(u.query).items()}
    get = lambda k, d="": (q.get(k, [d])[0] or d)
    flow = get("flow", "")
    sni = get("sni", "") or get("server_name", "")
    pbk = get("pbk", "")
    sid = get("sid", "")
    fp  = get("fp", "") or get("fingerprint", "")
    net = get("type", "tcp").lower()
    sec = get("security", "").lower()

    outbound = {
        "type": "vless",
        "tag": "proxy",
        "server": host,
        "server_port": port,
        "uuid": uuid,
    }
    if flow: outbound["flow"] = flow
    if net and net != "tcp":
        outbound["transport"] = {"type": net}

    if sec == "reality" or pbk:
        outbound["tls"] = {
            "enabled": True,
            "server_name": sni or host,
            "reality": {"enabled": True, "public_key": pbk, "short_id": sid},
            "utls": {"enabled": True, "fingerprint": fp or "chrome"}
        }
    elif sni:
        outbound["tls"] = {"enabled": True, "server_name": sni}
        if fp:
            outbound["tls"]["utls"] = {"enabled": True, "fingerprint": fp}
    return outbound

# ---------------- Robust fetch ----------------
_BROWSER_HEADERS = [
    {"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119 Safari/537.36",
     "Accept":"text/plain,*/*;q=0.9","Accept-Language":"ru,en-US;q=0.9,en;q=0.8","Referer":"https://live-fund.ru/"},
    {"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119 Safari/537.36",
     "Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8","Accept-Language":"ru,en-US;q=0.9,en;q=0.8","Referer":"https://live-fund.ru/"},
    {"User-Agent":"curl/8.3.0","Accept":"*/*"},
]

def _download_with_variants(url: str) -> str:
    last_info = ""
    for verify in (True, False):
        for hdr in _BROWSER_HEADERS:
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    r = requests.get(url, headers=hdr, timeout=10, allow_redirects=True, verify=verify)
                txt = r.text if r.encoding else r.content.decode("utf-8", errors="ignore")
                uri = _extract_first_uri_from_text(txt or "")
                if uri:
                    return txt or ""
                last_info = f"HTTP {r.status_code}, CT={r.headers.get('content-type','')}, sample={re.sub(r'\\s+',' ',(txt or ''))[:180]}"
            except Exception as e:
                last_info = f"err={e}"
    raise RuntimeError(f"fetch подписки без VLESS: {last_info}")

# ---------------- Patch helpers ----------------
def _patch_tun_alias(cfg_obj: dict, alias: str):
    for ib in cfg_obj.get("inbounds", []) or []:
        if isinstance(ib, dict) and ib.get("type") == "tun":
            ib.setdefault("tun", {})
            ib["interface_name"] = alias
            return

def _ensure_inbounds(cfg_obj: dict, profile: str):
    inbounds = cfg_obj.setdefault("inbounds", [])
    has_tun = any(isinstance(ib, dict) and ib.get("type") == "tun" for ib in inbounds)
    has_mixed = any(isinstance(ib, dict) and ib.get("type") == "mixed" for ib in inbounds)

    if not has_tun:
        inbounds.insert(0, {
            "type": "tun",
            "tag": "tun-in",
            "tun": {
                "interface_name": f"lf_tun_{profile}",
                "stack": "system",
                "auto_route": True,
                "strict_route": True
            }
        })
    else:
        _patch_tun_alias(cfg_obj, f"lf_tun_{profile}")

    if not has_mixed:
        inbounds.append({
            "type": "mixed",
            "tag": "mixed-in",
            "listen": "127.0.0.1",
            "listen_port": 7890
        })

def _ensure_dns_and_resolver(cfg_obj: dict):
    """Legacy DNS servers (strings) for maximal compatibility; no default_domain_resolver tag."""
    dns = cfg_obj.setdefault("dns", {})
    servers = dns.setdefault("servers", [])
    # if already present, leave as-is
    if not servers:
        servers[:] = ["https://1.1.1.1/dns-query", "8.8.8.8", "1.1.1.1"]
    # Do NOT set route.default_domain_resolver when using legacy format.

def _ensure_outbounds_base(cfg_obj: dict):
    _ensure_dns_and_resolver(cfg_obj)
    outs = cfg_obj.setdefault("outbounds", [])
    if outs:
        outs[0]["tag"] = "proxy"
    else:
        outs.append({"type": "direct", "tag": "proxy"})
    has = lambda tag: any(isinstance(o, dict) and o.get("tag") == tag for o in outs)
    if not has("direct"): outs.append({"type": "direct", "tag": "direct"})
    if not has("block"): outs.append({"type": "block", "tag": "block"})
    route = cfg_obj.setdefault("route", {})
    route.setdefault("final", "proxy")

# ---------------- RU direct helpers ----------------
def _ru_domains_default() -> list[str]:
    return [
        ".ru", ".su", ".xn--p1ai",
        "sber.ru","sberbank.ru","tinkoff.ru","vtb.ru","alfabank.ru","gazprombank.ru","qiwi.com","yoomoney.ru","yandex.money",
        "gosuslugi.ru","nalog.ru","pfr.gov.ru","rosreestr.ru","mos.ru","mosreg.ru",
        "yandex.ru","yandex.net","mail.ru","bk.ru","inbox.ru","list.ru","rambler.ru",
        "vk.com","vk.ru","ok.ru","telegram.org",
        "ozon.ru","wildberries.ru","sbermegamarket.ru","dns-shop.ru","citilink.ru","avito.ru","hh.ru",
        "steampowered.com","steamcommunity.com","steamstatic.com",
    ]

def _ru_flag_path(profile: str, which: str) -> Path:
    return _profile_dir(profile) / f"ru_direct.{which}"

def _should_ru_direct(profile: str) -> bool:
    if _ru_flag_path(profile, "on").exists(): return True
    if _ru_flag_path(profile, "off").exists(): return False
    return os.environ.get("LFTUN_RU_DIRECT", "1") not in ("0","false","off","no")

# ---------------- Build per-profile config ----------------
def _make_profile_cfg_from_subscription(profile: str) -> Path | None:
    sub_file = _profile_sub(profile)
    if not sub_file.exists():
        return _profile_cfg(profile) if _profile_cfg(profile).exists() else None

    source = sub_file.read_text(encoding="utf-8").strip()
    if not source: raise RuntimeError("subscription.txt пустой")

    if source.lower().startswith("vless://"):
        txt = source
    elif source.lower().startswith("http"):
        txt = _download_with_variants(source)
    else:
        txt = source

    uri = _extract_first_uri_from_text(txt or "")
    if not uri: raise RuntimeError("в тексте нет vless://")

    outbound = _parse_vless(uri)
    if not DEFAULT_CONFIG_PATH or not DEFAULT_CONFIG_PATH.exists():
        raise RuntimeError("базовый config/config.json не найден")
    try:
        base = json.loads(DEFAULT_CONFIG_PATH.read_text(encoding="utf-8", errors="ignore"))
    except Exception as e:
        raise RuntimeError(f"ошибка чтения базового config.json: {e}")

    outs = base.get("outbounds") or []
    if outs: outs[0] = outbound
    else: base["outbounds"] = [outbound]

    _ensure_inbounds(base, profile=profile)
    _ensure_outbounds_base(base)

    cfg_path = _profile_cfg(profile)
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text(json.dumps(base, ensure_ascii=False, indent=2), encoding="utf-8")

    try:
        exc = _exc_load(profile)
        _build_runtime_config(cfg_path, exc, profile=profile)
    except Exception:
        pass
    return cfg_path

# ---------------- Exclusions / runtime ----------------
def _profile_exc_file(name: str) -> Path: return _profile_dir(name) / "exclusions.json"

def _exc_load(name: str) -> dict:
    fp = _profile_exc_file(name)
    try: return json.loads(fp.read_text(encoding="utf-8"))
    except Exception: return {"sites": [], "apps": []}

def _exc_save(name: str, data: dict):
    fp = _profile_exc_file(name)
    try:
        fp.parent.mkdir(parents=True, exist_ok=True)
        fp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception: pass

def _build_runtime_config(base_cfg_path: Path, exc: dict, profile: str) -> Path:
    try:
        base = json.loads(base_cfg_path.read_text(encoding="utf-8", errors="ignore"))
    except Exception as e:
        raise RuntimeError(f"Не удалось прочитать config.json: {e}")

    _ensure_inbounds(base, profile=profile)
    _ensure_outbounds_base(base)
    # туннель по имени профиля
    for ib in base.get("inbounds", []):
        if ib.get("type") == "tun":
            ib["interface_name"] = f"lf_tun_{profile}"

    route = base.setdefault("route", {})
    rules = [r for r in route.setdefault("rules", []) if not (isinstance(r, dict) and ("geoip" in r or "rule_set" in r))]
    new_rules = []

    sites = list(dict.fromkeys(exc.get("sites", [])))
    if sites: new_rules.append({"domain_suffix": sites, "outbound": "direct"})
    apps = list(dict.fromkeys(exc.get("apps", [])))
    if apps:
        names = [Path(p).name for p in apps]
        new_rules.append({"process_name": names, "outbound": "direct"})
        new_rules.append({"process_path": apps, "outbound": "direct"})

    if _should_ru_direct(profile):
        ru_sites = _ru_domains_default()
        new_rules.append({"domain_suffix": ru_sites, "outbound": "direct"})

    route["rules"] = new_rules + rules

    out = _profile_runtime(base_cfg_path.parent.name)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(base, ensure_ascii=False, indent=2), encoding="utf-8")
    return out

# ---------------- Process / logs ----------------
log_q: "queue.Queue[str]" = queue.Queue(maxsize=10000)
TAIL_STOP = threading.Event()
_proc = None
_proc_lock = threading.Lock()
_action_lock = threading.Lock()

def qput(s: str):
    try: log_q.put_nowait(s)
    except queue.Full: pass

def _wait_stopped(timeout=4.0):
    t0 = time.time()
    while time.time() - t0 < timeout:
        with _proc_lock:
            if not (_proc and _proc.poll() is None):
                return True
        time.sleep(0.05)
    return False

def kill_singbox_sync():
    with _proc_lock: p = _proc
    if not p: qput("[LFTUN] not running"); return True
    try:
        try: p.terminate()
        except Exception: pass
        if not _wait_stopped(1.5):
            if os.name == "nt":
                try: subprocess.run(["taskkill", "/PID", str(p.pid), "/T", "/F"],
                                    capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
                except Exception: pass
            if not _wait_stopped(1.5):
                try: p.kill()
                except Exception: pass
        TAIL_STOP.set()
        ok = _wait_stopped(1.5)
        qput("[LFTUN] terminated" if ok else "[LFTUN] terminate timeout")
        return ok
    except Exception as e:
        qput(f"[kill] {e}"); return False

def _start_tail(log_path: Path):
    global TAIL_STOP
    TAIL_STOP.set(); time.sleep(0.1); TAIL_STOP = threading.Event()
    def tail():
        try:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            with open(log_path, "a", encoding="utf-8", errors="ignore"): pass
            with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
                f.seek(0,2)
                while not TAIL_STOP.is_set():
                    chunk = f.read()
                    if chunk:
                        for line in chunk.splitlines():
                            qput(line)
                    time.sleep(0.25)
        except Exception as e:
            qput(f"[tail] {e}")
    threading.Thread(target=tail, daemon=True).start()

def _read_tail(log_path: Path, max_lines=40) -> str:
    try:
        if not log_path.exists(): return "(лог отсутствует)"
        txt = log_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        return "\\n".join(txt[-max_lines:]) if txt else "(лог пуст)"
    except Exception as e:
        return f"(ошибка чтения лога: {e})"

def run_singbox(cfg: Path, log_path: Path):
    global _proc
    try:
        if not SINGBOX_BIN: qput("[ERR] sing-box не найден"); return
        if not cfg or not cfg.exists(): qput("[ERR] config.json не найден"); return
        _start_tail(log_path)
        qput(f"[LFTUN] start: {SINGBOX_BIN} run -c {cfg}  (log → {log_path})")
        creation = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        log_fh = open(log_path, "a", encoding="utf-8", errors="ignore")
        p = subprocess.Popen([str(SINGBOX_BIN), "run", "-c", str(cfg)],
                             stdout=log_fh, stderr=subprocess.STDOUT,
                             cwd=str(EXE_DIR),
                             creationflags=creation)
        with _proc_lock: _proc = p
        time.sleep(0.4)
        code_now = p.poll()
        if code_now is not None:
            qput(f"[LFTUN] exit(code={code_now}) сразу после запуска. Хвост лога:")
            qput(_read_tail(log_path, 60))
        code = p.wait()
        qput(f"[LFTUN] exit code={code}")
    except Exception as e:
        qput(f"[ERR] {e}")
    finally:
        with _proc_lock: _proc = None
        try: log_fh.close()
        except Exception: pass
        TAIL_STOP.set()

def set_interface_metric(alias: str, metric: int = 5):
    if os.name != "nt": return
    try:
        subprocess.Popen(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                          f"Try {{ Set-NetIPInterface -InterfaceAlias '{alias}' -InterfaceMetric {metric} -ErrorAction Stop }} Catch {{}}"],
                         creationflags=subprocess.CREATE_NO_WINDOW)
        qput(f"[metric] set {alias}={metric}")
    except Exception as e:
        qput(f"[metric] {e}")

def _cleanup_child():
    try: kill_singbox_sync()
    except Exception: pass
atexit.register(_cleanup_child)

# ---------------- IP helper ----------------
def get_external_ip(timeout=3) -> str:
    urls = ["https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"]
    for u in urls:
        try:
            import requests
            t = requests.get(u, timeout=timeout).text.strip()
            if t: return t
        except Exception: pass
    return "—"

# ---------------- UI ----------------
class App(tb.Window):
    MAX_LOG_LINES = 1500
    MAX_INSERT_LINES = 80
    MAX_INSERT_CHARS = 8000

    def __init__(self):
        super().__init__(title="LFTUN", themename="darkly")
        self.geometry("900x560"); self.minsize(760,480)

        profrow = tb.Frame(self, padding=(10,8,10,0)); profrow.pack(fill=X)
        tb.Label(profrow, text="Профиль:").pack(side=LEFT, padx=(0,6))
        self.profile_var = tk.StringVar(value="")
        self.profile_combo = tb.Combobox(profrow, textvariable=self.profile_var, state="readonly", width=28)
        self.profile_combo.pack(side=LEFT)
        self.profile_combo.bind("<<ComboboxSelected>>", lambda e: self._set_active(self.profile_var.get().strip(), restart=True))
        tb.Button(profrow, text="Добавить", bootstyle=PRIMARY, command=self.on_profile_add).pack(side=LEFT, padx=6)
        tb.Button(profrow, text="Удалить", command=self.on_profile_del).pack(side=LEFT, padx=6)
        tb.Button(profrow, text="Обновить", command=self.on_profile_update).pack(side=LEFT, padx=6)

        box = tb.Frame(self, padding=8); box.pack(padx=10, pady=(6,6))
        row = tb.Frame(box); row.pack(anchor=CENTER, pady=2)
        tb.Button(row, text="Добавить сайт", command=self.on_add_site).pack(side=LEFT, padx=6)
        tb.Button(row, text="Добавить приложение", command=self.on_add_app).pack(side=LEFT, padx=6)
        tb.Button(row, text="Показать исключения", command=self.on_show_exc).pack(side=LEFT, padx=6)

        center = tb.Frame(self, padding=10); center.pack(fill=X)
        self.logo = _logo(96); tb.Label(center, image=self.logo).pack(pady=(6, 12))
        center_row = tb.Frame(center); center_row.pack()
        self.tunnel_toggle = tb.Checkbutton(center_row, text="Туннель", bootstyle="success,round-toggle", command=self.on_tunnel_toggle)
        self.tunnel_toggle.pack(side=LEFT, padx=8)

        status = tb.Frame(self, padding=(10, 0, 10, 6)); status.pack(fill=X)
        self.status_lbl = tb.Label(status, text="Статус: отключено", anchor=W); self.status_lbl.pack(fill=X)
        self.ip_lbl = tb.Label(status, text="IP: —", anchor=W, foreground="#8ecbff"); self.ip_lbl.pack(fill=X)

        body = tb.Frame(self, padding=10); body.pack(fill=BOTH, expand=YES)
        self.log = tkst.ScrolledText(body, height=18, font=("Consolas",10)); self.log.pack(fill=BOTH, expand=YES)

        self._buf = []; self._last_flush = 0.0; self._flush_interval = 0.18
        self.after(180, self._pump_logs)

        self.cfg_lbl = tb.Label(self, text="config: —", anchor=W, font=("Consolas", 9))
        self.cfg_lbl.pack(fill=X, padx=10, pady=(0,8))

        self._proc_watch_running = False
        self._ip_loop_stop = threading.Event()

        self._refresh_profiles()
        act = _read_active_name()
        if act: self._set_active(act, restart=False)

        self.protocol("WM_DELETE_WINDOW", self.on_close)

    # --- лог-пайп
    def _update_cfg_label(self, p: Path | None = None):
        self.cfg_lbl.configure(text=f"config: {str(p) if p else '—'}")

    def append_log(self, s: str):
        try: log_q.put_nowait(s)
        except queue.Full: pass

    def _trim_tail(self):
        try:
            total = int(self.log.index('end-1c').split('.')[0])
            if total > self.MAX_LOG_LINES:
                self.log.delete("1.0", f"{total - self.MAX_LOG_LINES}.0")
        except Exception: pass

    def _flush_ui(self):
        if not self._buf: return
        lines = []; chars = 0
        while self._buf and len(lines) < self.MAX_INSERT_LINES and chars < self.MAX_INSERT_CHARS:
            s = self._buf.pop(0); lines.append(s); chars += len(s)+1
        self.log.insert(tk.END, "\\n".join(lines) + "\\n")
        self._trim_tail(); self.log.see(tk.END)

    def _pump_logs(self):
        pulled = 0
        try:
            while pulled < 500:
                line = log_q.get_nowait(); self._buf.append(line); pulled += 1
        except queue.Empty: pass
        now = time.perf_counter()
        if now - self._last_flush >= self._flush_interval:
            self._flush_ui(); self._last_flush = now
        self.after(180, self._pump_logs)

    # --- profiles
    def _refresh_profiles(self):
        names = _list_profiles()
        self.profile_combo["values"] = names
        act = _read_active_name()
        if act and act in names:
            self.profile_var.set(act)
        elif names:
            self.profile_var.set(names[0]); _write_active_name(names[0])
        else:
            self.profile_var.set("")

    def _ensure_profile_built(self, name: str):
        try:
            built = _make_profile_cfg_from_subscription(name)
            if built:
                self.append_log(f"[profile:{name}] config из подписки → {built} sha1={_cfg_fp(built)} {_cfg_hint(built)}")
            else:
                self.append_log(f"[profile:{name}] подписка есть, но config.json не создан (нет данных для сборки)")
            base = _profile_cfg(name)
            if base.exists():
                rt = _build_runtime_config(base, _exc_load(name), profile=name)
                self.append_log(f"[profile:{name}] runtime обновлён → {rt} sha1={_cfg_fp(rt)}")
        except Exception as e:
            self.append_log(f"[profile:{name}] ошибка сборки из подписки: {e}")

    def _set_active(self, name: str, restart=False):
        if not name: return
        _write_active_name(name)
        self.profile_var.set(name)
        self._ensure_profile_built(name)
        eff = _effective_cfg_for(name)
        self._update_cfg_label(eff)
        try:
            self.append_log(f"[profile] active={name} cfg={eff or '(нет)'} {('sha1='+_cfg_fp(Path(eff))) if eff else ''} {(_cfg_hint(Path(eff)) if eff else '')}")
        except Exception:
            pass
        if restart and self.tunnel_toggle.instate(['selected']):
            self.safe_restart()
        else:
            self.ip_lbl.configure(text="IP: —")

    def _ask_link_or_file(self) -> str | None:
        win = tk.Toplevel(self); win.title("Источник"); win.transient(self); win.grab_set(); win.resizable(False, False)
        frm = tb.Frame(win, padding=12); frm.pack(fill=BOTH, expand=YES)
        tb.Label(frm, text="Импортировать в профиль:", anchor="w").pack(anchor="w", pady=(0,6))
        res = {"mode": None}
        def choose(m): res["mode"]=m; win.destroy()
        row = tb.Frame(frm); row.pack(pady=(6,2))
        tb.Button(row, text="Ссылка (подписка)", bootstyle=PRIMARY, command=lambda: choose("link")).pack(side=LEFT, padx=6)
        tb.Button(row, text="Файл config.json", command=lambda: choose("file")).pack(side=LEFT, padx=6)
        tb.Button(frm, text="Отмена", command=lambda: choose(None)).pack(pady=(10,0))
        win.update_idletasks()
        x=self.winfo_rootx()+(self.winfo_width()-win.winfo_width())//2; y=self.winfo_rooty()+(self.winfo_height()-win.winfo_height())//2
        win.geometry(f"+{max(x,0)}+{max(y,0)}"); win.wait_window()
        return res["mode"]

    def ask_subscription_url(self):
        win = tk.Toplevel(self); win.title("Подписка"); win.transient(self); win.grab_set(); win.resizable(False, False)
        frame = tb.Frame(win, padding=12); frame.pack(fill=tk.BOTH, expand=True)
        tb.Label(frame, text="Вставь ссылку подписки (https://… или vless://…)", anchor="w").pack(anchor="w", pady=(0,6))
        var = tk.StringVar(); entry = tb.Entry(frame, textvariable=var, width=54); entry.pack(fill=tk.X); entry.focus_set()
        def do_paste(_=None):
            try: entry.event_generate("<<Paste>>")
            except Exception:
                try: entry.insert("insert", win.clipboard_get())
                except Exception: pass
            return "break"
        entry.bind("<Control-v>", do_paste); entry.bind("<Control-V>", do_paste)
        entry.bind("<Shift-Insert>", do_paste)
        entry.bind("<Control-KeyPress>", lambda e: do_paste() if e.keysym.lower() in ("v",) else None)
        menu = tk.Menu(entry, tearoff=0); menu.add_command(label="Вставить", command=do_paste)
        entry.bind("<Button-3>", lambda e: (menu.tk_popup(e.x_root, e.y_root), "break"))
        btns = tb.Frame(frame); btns.pack(fill=tk.X, pady=(10,0))
        res = {"val": None}
        def ok(): res["val"]=var.get().strip(); win.destroy()
        def cancel(): res["val"]=None; win.destroy()
        tb.Button(btns, text="Отмена", command=cancel).pack(side=tk.RIGHT)
        tb.Button(btns, text="OK", bootstyle=PRIMARY, command=ok).pack(side=tk.RIGHT, padx=(6,0))
        win.bind("<Return>", lambda e: ok()); win.bind("<Escape>", lambda e: cancel())
        win.update_idletasks(); x=self.winfo_rootx()+(self.winfo_width()-win.winfo_width())//2; y=self.winfo_rooty()+(self.winfo_height()-win.winfo_height())//2
        win.geometry(f"+{max(x,0)}+{max(y,0)}"); win.wait_window(); return res["val"]

    def on_profile_add(self):
        name = simpledialog.askstring("Новый профиль", "Имя профиля (латиница/цифры/дефис):", parent=self)
        if not name: return
        name = re.sub(r"[^A-Za-z0-9._-]+", "_", name.strip())
        d = _profile_dir(name); d.mkdir(parents=True, exist_ok=True)
        mode = self._ask_link_or_file()
        if mode == "link":
            url = self.ask_subscription_url()
            if url:
                _profile_sub(name).write_text(url.strip(), encoding="utf-8")
                self.append_log(f"[profile:{name}] подписка сохранена → {_profile_sub(name)}")
        elif mode == "file":
            path = filedialog.askopenfilename(title="Выбери config.json", filetypes=[("JSON","*.json"),("Все файлы","*.*")])
            if path and path.lower().endswith(".json"):
                shutil.copy2(path, _profile_cfg(name)); self.append_log(f"[profile:{name}] config импортирован → {_profile_cfg(name)}")
        self._ensure_profile_built(name)
        self._refresh_profiles(); self._set_active(name, restart=False)

    def on_profile_del(self):
        name = self.profile_var.get().strip()
        if not name: return
        if not tb.dialogs.Messagebox.yesno("Удалить профиль?", f"Профиль «{name}» будет удалён вместе с файлами. Продолжить?"): return
        try: shutil.rmtree(_profile_dir(name), ignore_errors=True); self.append_log(f"[profile:{name}] удалён")
        except Exception as e: self.append_log(f"[profile:{name}] ошибка удаления: {e}")
        self._refresh_profiles()
        names = _list_profiles()
        if names: self._set_active(names[0], restart=False)
        else: self._update_cfg_label(None)

    def on_profile_update(self):
        name = self.profile_var.get().strip()
        if not name: return
        mode = self._ask_link_or_file()
        if mode == "link":
            url = self.ask_subscription_url()
            if url:
                _profile_sub(name).write_text(url.strip(), encoding="utf-8")
                self.append_log(f"[profile:{name}] подписка сохранена → {_profile_sub(name)}")
                self._ensure_profile_built(name)
        elif mode == "file":
            path = filedialog.askopenfilename(title="Выбери config.json", filetypes=[("JSON","*.json"),("Все файлы","*.*")])
            if path and path.lower().endswith(".json"):
                shutil.copy2(path, _profile_cfg(name)); self.append_log(f"[profile:{name}] config импортирован → {_profile_cfg(name)}")
        self._set_active(name, restart=False)

    # --- exclusions
    def on_add_site(self):
        name = self.profile_var.get().strip()
        if not name: messagebox.showwarning("Исключения", "Сначала выберите профиль."); return
        data = _exc_load(name)
        dom = simpledialog.askstring("Добавить сайт", "Домен или суффикс (example.com):")
        if not dom: return
        dom = dom.strip()
        if dom and dom not in data["sites"]:
            data["sites"].append(dom); _exc_save(name, data)
            self.append_log(f"[exc:{name}] +site {dom}"); self.apply_exclusions(restart_if_running=True)

    def on_add_app(self):
        name = self.profile_var.get().strip()
        if not name: messagebox.showwarning("Исключения", "Сначала выберите профиль."); return
        data = _exc_load(name)
        path = filedialog.askopenfilename(title="Выбери .exe приложения", filetypes=[("EXE","*.exe"),("Все файлы","*.*")])
        if not path: return
        if path not in data["apps"]:
            data["apps"].append(path); _exc_save(name, data)
            self.append_log(f"[exc:{name}] +app {path}"); self.apply_exclusions(restart_if_running=True)

    def on_show_exc(self):
        name = self.profile_var.get().strip()
        if not name: messagebox.showwarning("Исключения", "Сначала выберите профиль."); return
        data = _exc_load(name)

        win = tk.Toplevel(self); win.title(f"Исключения — {name}"); win.transient(self); win.grab_set(); win.resizable(False, False)
        frm = tb.Frame(win, padding=12); frm.pack(fill=tk.BOTH, expand=True)

        tb.Label(frm, text="Сайты (domain suffix):", anchor="w").grid(row=0, column=0, sticky="w")
        sites_lb = tk.Listbox(frm, height=8, width=48); sites_lb.grid(row=1, column=0, sticky="w")
        for s in data.get("sites", []): sites_lb.insert(tk.END, s)

        tb.Label(frm, text="Приложения (.exe):", anchor="w").grid(row=0, column=1, sticky="w", padx=(16,0))
        apps_lb = tk.Listbox(frm, height=8, width=48); apps_lb.grid(row=1, column=1, sticky="w", padx=(16,0))
        for a in data.get("apps", []): apps_lb.insert(tk.END, a)

        btns = tb.Frame(frm); btns.grid(row=2, column=0, columnspan=2, pady=(10,0))
        def del_selected():
            changed = False
            si = list(sites_lb.curselection()); ai = list(apps_lb.curselection())
            if si:
                for idx in reversed(si):
                    val = sites_lb.get(idx); sites_lb.delete(idx)
                    if val in data["sites"]: data["sites"].remove(val); changed = True
            if ai:
                for idx in reversed(ai):
                    val = apps_lb.get(idx); apps_lb.delete(idx)
                    if val in data["apps"]: data["apps"].remove(val); changed = True
            if changed:
                _exc_save(name, data); self.apply_exclusions(restart_if_running=True)

        def del_all():
            if not tb.dialogs.Messagebox.yesno("Удалить все исключения?", "Подтвердите"):
                return
            data["sites"] = []; data["apps"] = []
            sites_lb.delete(0, tk.END); apps_lb.delete(0, tk.END)
            _exc_save(name, data); self.apply_exclusions(restart_if_running=True)

        tb.Button(btns, text="Удалить выбранное", bootstyle=DANGER, command=del_selected).pack(side=LEFT, padx=6)
        tb.Button(btns, text="Удалить всё", command=del_all).pack(side=LEFT, padx=6)
        tb.Button(btns, text="Закрыть", command=win.destroy).pack(side=LEFT, padx=6)

        win.update_idletasks()
        x=self.winfo_rootx()+(self.winfo_width()-win.winfo_width())//2; y=self.winfo_rooty()+(self.winfo_height()-win.winfo_height())//2
        win.geometry(f"+{max(x,0)}+{max(y,0)}")

    def apply_exclusions(self, restart_if_running=False):
        name = self.profile_var.get().strip()
        if not name: self.append_log("[exc] профиль не активен"); return
        base_path = _profile_cfg(name)
        if not base_path.exists():
            self.append_log(f"[exc:{name}] base config.json нет"); return
        try:
            new_cfg = _build_runtime_config(base_path, _exc_load(name), profile=name)
            self._update_cfg_label(new_cfg)
            self.append_log(f"[exc:{name}] применены → {new_cfg} sha1={_cfg_fp(new_cfg)}")
            if restart_if_running and self.tunnel_toggle.instate(['selected']):
                self.safe_restart()
        except Exception as e:
            self.append_log(f"[exc:{name}] ошибка: {e}")

    # --- watchers
    def _ensure_proc_watch(self):
        if hasattr(self, "_proc_watch_running") and self._proc_watch_running: return
        self._proc_watch_running = True
        def loop():
            while True:
                time.sleep(1.0)
                sel = self.tunnel_toggle.instate(['selected'])
                with _proc_lock: p = _proc
                dead = (p is None) or (p.poll() is not None)
                if sel and dead:
                    self.after(0, lambda: (self.tunnel_toggle.state(['!selected']),
                                           self.status_lbl.configure(text="Статус: отключено"),
                                           self.ip_lbl.configure(text="IP: —")))
        threading.Thread(target=loop, daemon=True).start()

    def _check_started_ok(self):
        with _proc_lock: p = _proc
        if p is None or p.poll() is not None:
            self.tunnel_toggle.state(['!selected'])
            self.status_lbl.configure(text="Статус: отключено")
            self.ip_lbl.configure(text="IP: —")

    def _ip_once(self):
        ip = get_external_ip()
        try:
            self.after(0, lambda ip=ip: self.ip_lbl.configure(text=f"IP: {ip}"))
        except Exception:
            pass

    # --- tunnel
    def on_tunnel_toggle(self):
        if not _action_lock.acquire(blocking=False):
            return
        try:
            if self.tunnel_toggle.instate(['selected']):
                if not ensure_admin_and_relaunch():
                    self.tunnel_toggle.state(['!selected']); return
                sel = self.profile_var.get().strip() or _read_active_name()
                if sel: self._ensure_profile_built(sel)
                eff = _effective_cfg_for(sel)
                if not eff or not Path(eff).exists():
                    self.status_lbl.configure(text="Статус: ошибка конфигурации")
                    messagebox.showwarning("LFTUN", "У профиля нет config.json. Нажми «Обновить» и импортируй «Ссылка (подписка)» или «Файл config.json».")
                    self.tunnel_toggle.state(['!selected']); return
                self._update_cfg_label(eff)
                self.append_log(f"[profile] use {sel or '(default)'} cfg={eff} sha1={_cfg_fp(Path(eff))} {_cfg_hint(Path(eff))}")
                self.status_lbl.configure(text="Статус: подключаю…")
                self.ip_lbl.configure(text="IP: …")
                threading.Thread(target=run_singbox, args=(Path(eff), _profile_log(sel or 'default')), daemon=True).start()
                # метрика интерфейса (Windows)
                alias = get_tun_alias_from_config(Path(eff)) or "LFTUN"
                try:
                    subprocess.Popen(["powershell","-NoProfile","-ExecutionPolicy","Bypass",
                                      f"Try {{ Set-NetIPInterface -InterfaceAlias '{alias}' -InterfaceMetric 5 -ErrorAction Stop }} Catch {{}}"],
                                     creationflags=subprocess.CREATE_NO_WINDOW if os.name=="nt" else 0)
                except Exception: pass
                self._ensure_proc_watch()
                self.after(1000, self._check_started_ok)
                threading.Thread(target=self._ip_once, daemon=True).start()
                self.after(300, lambda: self.status_lbl.configure(text="Статус: подключено"))
            else:
                self.status_lbl.configure(text="Статус: отключаю…")
                def off():
                    self._ip_loop_stop.set()
                    kill_singbox_sync()
                    self.after(0, lambda: (self.status_lbl.configure(text="Статус: отключено"),
                                           self.ip_lbl.configure(text="IP: —")))
                threading.Thread(target=off, daemon=True).start()
        finally:
            self.after(350, lambda: _action_lock.release())

    def safe_restart(self):
        def do():
            _action_lock.acquire()
            try:
                self._ip_loop_stop.set()
                kill_singbox_sync(); time.sleep(0.2)
                sel = self.profile_var.get().strip() or _read_active_name()
                if sel: self._ensure_profile_built(sel)
                eff = _effective_cfg_for(sel)
                if not eff or not Path(eff).exists():
                    self.append_log("[restart] нет профильного config.json — отмена")
                    self.after(0, lambda: self.tunnel_toggle.state(['!selected']))
                    return
                self._update_cfg_label(eff)
                self.append_log(f"[profile] restart with {sel or '(default)'} cfg={eff} sha1={_cfg_fp(Path(eff))} {_cfg_hint(Path(eff))}")
                self.status_lbl.configure(text="Статус: подключаю…")
                self.ip_lbl.configure(text="IP: …")
                threading.Thread(target=run_singbox, args=(Path(eff), _profile_log(sel or 'default')), daemon=True).start()
                self.after(220, lambda: self.status_lbl.configure(text="Статус: подключено"))
                self.after(1000, self._check_started_ok)
                threading.Thread(target=self._ip_once, daemon=True).start()
            finally:
                self.after(350, lambda: _action_lock.release())
        threading.Thread(target=do, daemon=True).start()

    def on_close(self):
        try: self._ip_loop_stop.set(); kill_singbox_sync()
        except: pass
        self.after(120, self.destroy)

if __name__ == "__main__":
    app = App()
    app.mainloop()
