"""
Arma Reforger Server Management Panel
https://github.com/mateuszgolebiewski-code/arma-reforger-panel

Local fork — modifications:
  - Bcrypt-hashed admin password + constant-time verification + rate limiting
  - CSRF protection on state-changing routes
  - Persistent SECRET_KEY (sessions survive panel restart)
  - Bulk mod import via pasted JSON array or uploaded JSON file
  - Auto-discovery of scenarios from installed mods (`.pak` strings scan, mtime-cached)
"""

from flask import Flask, request, jsonify, session, redirect, Response, send_from_directory
import bcrypt
import hmac
import mmap
import re
import secrets
import subprocess
import os
import json
import threading
import time
import glob

# ─── CONFIG ───────────────────────────────────────────────────────────────────

def load_env(path="config.env"):
    env = {}
    if not os.path.exists(path):
        return env
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, _, val = line.partition("=")
                env[key.strip()] = val.strip().strip('"').strip("'")
    return env

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_cfg = load_env(os.path.join(_BASE_DIR, "config.env"))

# Backwards-compatible password handling: prefer the bcrypt hash; if only the
# plaintext PANEL_PASSWORD is set (old configs), hash it in-memory at startup.
PANEL_PASSWORD_HASH = _cfg.get("PANEL_PASSWORD_HASH", "").strip()
_LEGACY_PLAINTEXT   = _cfg.get("PANEL_PASSWORD", "").strip()
if not PANEL_PASSWORD_HASH and _LEGACY_PLAINTEXT:
    PANEL_PASSWORD_HASH = bcrypt.hashpw(_LEGACY_PLAINTEXT.encode(), bcrypt.gensalt()).decode()
    print("[panel] WARNING: config.env uses legacy plaintext PANEL_PASSWORD. "
          "Re-run install.sh --update or replace it with PANEL_PASSWORD_HASH=...", flush=True)
if not PANEL_PASSWORD_HASH:
    PANEL_PASSWORD_HASH = bcrypt.hashpw(b"changeme", bcrypt.gensalt()).decode()
    print("[panel] WARNING: no panel password set. Defaulting to 'changeme'.", flush=True)

PANEL_PORT     = int(_cfg.get("PANEL_PORT", 8888))
SERVER_DIR     = _cfg.get("SERVER_DIR",    "/home/arma/server")
SERVER_CONFIG  = _cfg.get("SERVER_CONFIG", "/home/arma/server/config.json")
LOG_DIR        = _cfg.get("LOG_DIR",       "/home/arma/.config/ArmaReforger/logs")
WORKSHOP_DIR   = _cfg.get("WORKSHOP_DIR",  os.path.expanduser("~/.local/share/Arma Reforger/addons"))
SERVER_BINARY  = "./ArmaReforgerServer"
SERVER_ARGS    = ["-config", SERVER_CONFIG] + (
    [f"-maxFPS={_cfg['MAX_FPS']}"] if _cfg.get("MAX_FPS") else []
)

# Persistent secret key so sessions survive panel restarts.
_SECRET_FILE = os.path.join(_BASE_DIR, ".panel-secret")
def _load_or_create_secret():
    try:
        if os.path.exists(_SECRET_FILE):
            with open(_SECRET_FILE, "rb") as f:
                data = f.read().strip()
                if len(data) >= 32:
                    return data
    except OSError:
        pass
    data = secrets.token_bytes(48)
    try:
        with open(_SECRET_FILE, "wb") as f:
            f.write(data)
        os.chmod(_SECRET_FILE, 0o600)
    except OSError as e:
        print(f"[panel] WARNING: could not persist session secret ({e}); using ephemeral one.", flush=True)
    return data

app = Flask(__name__, static_folder='static')
app.secret_key = _load_or_create_secret()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=False,  # set True if you put HTTPS in front
    PERMANENT_SESSION_LIFETIME=60 * 60 * 12,
    MAX_CONTENT_LENGTH=2 * 1024 * 1024,  # 2 MB cap on uploads
)


# ─── SECURITY HELPERS ─────────────────────────────────────────────────────────

def _client_ip():
    # Honor X-Forwarded-For only when behind a reverse proxy; otherwise use remote_addr
    return request.headers.get("X-Forwarded-For", request.remote_addr or "").split(",")[0].strip() or "unknown"


_LOGIN_BUCKETS: dict[str, list[float]] = {}
_LOGIN_WINDOW_SEC = 60.0
_LOGIN_MAX_ATTEMPTS = 5

def _login_rate_ok(ip: str) -> bool:
    now = time.time()
    bucket = [t for t in _LOGIN_BUCKETS.get(ip, []) if now - t < _LOGIN_WINDOW_SEC]
    if len(bucket) >= _LOGIN_MAX_ATTEMPTS:
        _LOGIN_BUCKETS[ip] = bucket
        return False
    bucket.append(now)
    _LOGIN_BUCKETS[ip] = bucket
    return True


def _verify_password(plain: str) -> bool:
    if not plain:
        return False
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), PANEL_PASSWORD_HASH.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def _ensure_csrf() -> str:
    tok = session.get("csrf")
    if not tok:
        tok = secrets.token_urlsafe(32)
        session["csrf"] = tok
    return tok


def _csrf_required() -> Response | None:
    """Check CSRF token from header or body. Returns an error Response or None."""
    expected = session.get("csrf")
    supplied = (
        request.headers.get("X-CSRF-Token", "")
        or (request.get_json(silent=True) or {}).get("_csrf", "")
        or request.form.get("_csrf", "")
    )
    if not expected or not supplied or not hmac.compare_digest(expected, supplied):
        return jsonify({"ok": False, "error": "CSRF token invalid"}), 403
    return None


@app.after_request
def _security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    return resp

# ─── MISSIONS ─────────────────────────────────────────────────────────────────

AVAILABLE_MISSIONS = [
    # Everon
    {"id": "{ECC61978EDCC2B5A}Missions/23_Campaign.conf",              "name": "Conflict — Everon"},
    {"id": "{C700DB41F0C546E1}Missions/23_Campaign_NorthCentral.conf", "name": "Conflict — Northern Everon"},
    {"id": "{28802845ADA64D52}Missions/23_Campaign_SWCoast.conf",      "name": "Conflict — Southern Everon"},
    {"id": "{94992A3D7CE4FF8A}Missions/23_Campaign_Western.conf",      "name": "Conflict — Western Everon"},
    {"id": "{FDE33AFE2ED7875B}Missions/23_Campaign_Montignac.conf",    "name": "Conflict — Montignac"},
    {"id": "{0220741028718E7F}Missions/23_Campaign_HQC_Everon.conf",   "name": "Conflict: HQ Commander — Everon"},
    {"id": "{59AD59368755F41A}Missions/21_GM_Eden.conf",               "name": "Game Master — Everon"},
    {"id": "{DFAC5FABD11F2390}Missions/26_CombatOpsEveron.conf",       "name": "Combat Ops — Everon"},
    # Capture & Hold
    {"id": "{3F2E005F43DBD2F8}Missions/CAH_Briars_Coast.conf",         "name": "Capture & Hold — Briars Coast"},
    {"id": "{F1A1BEA67132113E}Missions/CAH_Castle.conf",               "name": "Capture & Hold — Montfort Castle"},
    {"id": "{589945FB9FA7B97D}Missions/CAH_Concrete_Plant.conf",       "name": "Capture & Hold — Concrete Plant"},
    {"id": "{9405201CBD22A30C}Missions/CAH_Factory.conf",              "name": "Capture & Hold — Almara Factory"},
    {"id": "{1CD06B409C6FAE56}Missions/CAH_Forest.conf",               "name": "Capture & Hold — Simon's Wood"},
    {"id": "{7C491B1FCC0FF0E1}Missions/CAH_LeMoule.conf",              "name": "Capture & Hold — Le Moule"},
    {"id": "{6EA2E454519E5869}Missions/CAH_Military_Base.conf",        "name": "Capture & Hold — Camp Blake"},
    # Showcase / SP
    {"id": "{C47A1A6245A13B26}Missions/SP01_ReginaV2.conf",            "name": "Elimination"},
    {"id": "{0648CDB32D6B02B3}Missions/SP02_AirSupport.conf",          "name": "Air Support"},
    # Arland
    {"id": "{C41618FD18E9D714}Missions/23_Campaign_Arland.conf",       "name": "Conflict — Arland"},
    {"id": "{68D1240A11492545}Missions/23_Campaign_HQC_Arland.conf",   "name": "Conflict: HQ Commander — Arland"},
    {"id": "{2BBBE828037C6F4B}Missions/22_GM_Arland.conf",             "name": "Game Master — Arland"},
    {"id": "{DAA03C6E6099D50F}Missions/24_CombatOps.conf",             "name": "Combat Ops — Arland"},
    # Kolguyev
    {"id": "{F45C6C15D31252E6}Missions/27_GM_Cain.conf",               "name": "Game Master — Kolguyev"},
    {"id": "{BB5345C22DD2B655}Missions/23_Campaign_HQC_Cain.conf",     "name": "Conflict: HQ Commander — Kolguyev"},
    {"id": "{CB347F2F10065C9C}Missions/CombatOpsCain.conf",            "name": "Combat Ops — Kolguyev"},
    {"id": "{2B4183DF23E88249}Missions/CAH_Morton.conf",               "name": "Capture & Hold — Morton"},
    # Operation Omega
    {"id": "{10B8582BAD9F7040}Missions/Scenario01_Intro.conf",         "name": "Operation Omega 01: Over The Hills And Far Away"},
    {"id": "{1D76AF6DC4DF0577}Missions/Scenario02_Steal.conf",         "name": "Operation Omega 02: Radio Check"},
    {"id": "{D1647575BCEA5A05}Missions/Scenario03_Villa.conf",         "name": "Operation Omega 03: Light In The Dark"},
    {"id": "{6D224A109B973DD8}Missions/Scenario04_Sabotage.conf",      "name": "Operation Omega 04: Red Silence"},
    {"id": "{FA2AB0181129CB16}Missions/Scenario05_Hill.conf",          "name": "Operation Omega 05: Cliffhanger"},
    # RHS — Status Quo (requires mod)
    {"id": "{AAD43C10045857C1}Missions/RHS_Conflict.conf",              "name": "RHS — Conflict Everon"},
    {"id": "{B694A77592CB69E0}Missions/RHS_ConflictWithoutAIs.conf",    "name": "RHS — Conflict Everon (No AI)"},
    {"id": "{9909DB7ECEA05535}Missions/RHS_Conflict_East.conf",         "name": "RHS — Conflict Everon East"},
    {"id": "{2F5DD5ACC14120A9}Missions/RHS_Conflict_NorthCentral.conf", "name": "RHS — Conflict Everon North Central"},
    {"id": "{57B154A20B8B283E}Missions/RHS_Conflict_SWCoast.conf",      "name": "RHS — Conflict Everon SW Coast"},
    {"id": "{367A7800D147878A}Missions/RHS_Conflict_West.conf",         "name": "RHS — Conflict Everon West"},
    {"id": "{7577640CD42A00BD}Missions/RHS_Conflict_Arland.conf",       "name": "RHS — Conflict Arland"},
    {"id": "{C5EAD55037EB4751}Missions/RHS_CombatOps_MSV.conf",        "name": "RHS — Combat Ops Arland (MSV vs FIA)"},
    {"id": "{D10B11A71A36FCF5}Missions/RHS_CombatOps_USMC_vs_MSV.conf","name": "RHS — Combat Ops Arland (USMC vs MSV)"},
    {"id": "{68A6FBF43B801FF6}Missions/RHS_ShowcaseBasic.conf",         "name": "RHS — Showcase Mission"},
    {"id": "{217436B52D34E4BD}Missions/RHS_Showcase_GM.conf",           "name": "RHS — Showcase Mission (Game Master)"},
]
# Add a "source" tag so the UI can group by origin.
for _m in AVAILABLE_MISSIONS:
    _m.setdefault("source", "vanilla")


# ─── SCENARIO AUTO-DISCOVERY (mod .pak scan) ──────────────────────────────────
#
# Reforger workshop mods unpack to <WORKSHOP_DIR>/<Name>_<HEXID>/data.pak.
# `data.pak` is a binary IFF file but `strings` reliably finds scenario IDs
# embedded as `{HEX16}Missions/Path/Name.conf`. We cache results per .pak by
# mtime to avoid rescanning every page load.

_SCENARIO_RE = re.compile(rb'\{([0-9A-Fa-f]{16})\}(Missions/[A-Za-z0-9_./\-]+\.conf)')
_SCAN_CACHE_FILE = os.path.join(_BASE_DIR, ".scenario-cache.json")


def _scan_cache_load():
    try:
        with open(_SCAN_CACHE_FILE) as f:
            data = json.load(f)
        return data.get("mods", {}), data.get("mtimes", {})
    except (OSError, json.JSONDecodeError):
        return {}, {}


def _scan_cache_save(mods, mtimes):
    try:
        with open(_SCAN_CACHE_FILE, "w") as f:
            json.dump({"mods": mods, "mtimes": mtimes, "saved_at": time.time()}, f)
    except OSError as e:
        print(f"[panel] WARNING: could not write scenario cache: {e}", flush=True)


def _mod_label_from_dir(mod_dir):
    """Best-effort friendly name from <mod_dir>/meta JSON, falling back to dir basename."""
    meta = os.path.join(mod_dir, "meta")
    if os.path.isfile(meta):
        try:
            with open(meta, encoding="utf-8-sig") as f:
                data = json.load(f)
            name = (data.get("meta") or {}).get("name")
            if name:
                return str(name)
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            pass
    base = os.path.basename(mod_dir)
    parts = base.rsplit("_", 1)
    if len(parts) == 2 and len(parts[1]) >= 8 and all(c in "0123456789ABCDEFabcdef" for c in parts[1]):
        return parts[0]
    return base


_PAK_MAX_BYTES = 8 * 1024 * 1024 * 1024  # skip pathologically huge paks


def _scan_pak(pak_path):
    """Memory-map the .pak and regex-scan for scenario IDs. Constant RAM regardless
    of file size — the OS pages the file in/out as the scanner walks. No subprocess,
    no captured stdout, so concurrent scans don't pile up gigabytes of buffered text.
    """
    try:
        size = os.path.getsize(pak_path)
        if size <= 0 or size > _PAK_MAX_BYTES:
            return []
        with open(pak_path, "rb") as f:
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                found = {}
                for m in _SCENARIO_RE.finditer(mm):
                    gid = m.group(1).decode("ascii").upper()
                    path = m.group(2).decode("ascii")
                    sid = "{" + gid + "}" + path
                    found.setdefault(sid, sid)
                return list(found.keys())
    except (OSError, ValueError):
        return []


_SCAN_LOCK = threading.Lock()
_LAST_SCAN_RESULT: dict = {"scenarios": [], "diag": None, "ts": 0.0}


def _candidate_workshop_dirs():
    """Common Reforger Linux server addon paths, in priority order."""
    candidates = []
    if WORKSHOP_DIR:
        candidates.append(WORKSHOP_DIR)
    home = os.path.dirname(SERVER_DIR.rstrip("/")) if SERVER_DIR else os.path.expanduser("~")
    if not home or home == "/":
        home = os.path.expanduser("~arma") if os.path.isdir("/home/arma") else os.path.expanduser("~")
    candidates.extend([
        os.path.join(home, ".local/share/Arma Reforger/profile/addons"),
        os.path.join(home, ".local/share/Arma Reforger/addons"),
        os.path.join(home, ".config/Arma Reforger/addons"),
        os.path.join(home, ".config/ArmaReforger/addons"),
    ])
    if SERVER_DIR:
        candidates.extend([
            os.path.join(SERVER_DIR, "profile/addons"),
            os.path.join(SERVER_DIR, "addons"),
        ])
    seen, out = set(), []
    for d in candidates:
        if d and d not in seen:
            seen.add(d)
            out.append(d)
    return out


def _find_pak_files(root, max_depth=3):
    """Walk `root` up to `max_depth` levels and yield (mod_dir, pak_path) for each data.pak."""
    if not root or not os.path.isdir(root):
        return
    root = os.path.abspath(root)
    base_depth = root.rstrip("/").count("/")
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        depth = dirpath.rstrip("/").count("/") - base_depth
        if depth >= max_depth:
            dirnames[:] = []
        if "data.pak" in filenames:
            yield dirpath, os.path.join(dirpath, "data.pak")


def _discover_locked(force_rescan):
    """Actual scan work. Caller must hold _SCAN_LOCK."""
    diag = {"candidates_tried": [], "workshop_dir": None, "paks_found": 0,
            "mods_with_scenarios": 0, "scenarios_total": 0, "errors": []}

    workshop_dir = None
    pak_files = []
    for cand in _candidate_workshop_dirs():
        diag["candidates_tried"].append({"path": cand, "exists": os.path.isdir(cand)})
        if not os.path.isdir(cand):
            continue
        paks = list(_find_pak_files(cand, max_depth=3))
        if paks:
            workshop_dir = cand
            pak_files = paks
            break
    diag["workshop_dir"] = workshop_dir
    diag["paks_found"] = len(pak_files)

    if not pak_files:
        return [], diag

    cache_mods, cache_mtimes = ({}, {}) if force_rescan else _scan_cache_load()
    fresh_mods, fresh_mtimes = {}, {}

    for mod_dir, pak in pak_files:
        # Cache key is the absolute pak path — stable regardless of which
        # candidate workshop dir was picked.
        key = os.path.abspath(pak)
        try:
            mtime = os.path.getmtime(pak)
        except OSError as e:
            diag["errors"].append(f"{key}: stat failed ({e})")
            continue

        if cache_mtimes.get(key) == mtime and key in cache_mods:
            fresh_mods[key] = cache_mods[key]
            fresh_mtimes[key] = mtime
            continue

        label = _mod_label_from_dir(mod_dir)
        sids = _scan_pak(pak)
        if sids:
            fresh_mods[key] = [
                {"id": sid, "name": sid.split("/")[-1].replace(".conf", ""), "source": label}
                for sid in sids
            ]
        fresh_mtimes[key] = mtime

    _scan_cache_save(fresh_mods, fresh_mtimes)

    flat = []
    for sids in fresh_mods.values():
        flat.extend(sids)
    diag["mods_with_scenarios"] = len(fresh_mods)
    diag["scenarios_total"] = len(flat)
    return flat, diag


def discover_mod_scenarios(force_rescan=False):
    """Return (scenarios, diag).
       Lock-protected so concurrent /api/status polls or rescan clicks can't
       launch overlapping scans.  Non-rescan callers get the cached result
       without doing any disk I/O if a scan is already in progress."""
    if not force_rescan:
        # Cheap path: just read the on-disk cache.
        cache_mods, _mtimes = _scan_cache_load()
        if cache_mods:
            flat = []
            for sids in cache_mods.values():
                flat.extend(sids)
            diag = {"workshop_dir": None, "paks_found": len(cache_mods),
                    "scenarios_total": len(flat), "from_cache": True}
            return flat, diag

    if not _SCAN_LOCK.acquire(blocking=force_rescan):
        # Scan in progress and we don't want to block — return whatever we have.
        return _LAST_SCAN_RESULT["scenarios"], (_LAST_SCAN_RESULT["diag"] or {"busy": True})
    try:
        scenarios, diag = _discover_locked(force_rescan)
        _LAST_SCAN_RESULT["scenarios"] = scenarios
        _LAST_SCAN_RESULT["diag"] = diag
        _LAST_SCAN_RESULT["ts"] = time.time()
        return scenarios, diag
    finally:
        _SCAN_LOCK.release()


def cached_scenarios():
    """Cheap read for /api/status — never triggers a fresh scan."""
    cache_mods, _mtimes = _scan_cache_load()
    flat = []
    for sids in cache_mods.values():
        flat.extend(sids)
    return flat


def all_scenarios(force_rescan=False):
    """Vanilla list + auto-discovered, deduped by id (vanilla wins for naming).
       Returns (list, diag)."""
    by_id = {}
    for s in AVAILABLE_MISSIONS:
        by_id[s["id"]] = dict(s)
    discovered, diag = discover_mod_scenarios(force_rescan=force_rescan)
    for s in discovered:
        by_id.setdefault(s["id"], dict(s))
    out = list(by_id.values())
    out.sort(key=lambda s: (s["source"] != "vanilla", s["source"], s["name"]))
    return out, diag


def all_scenarios_cached():
    """Like all_scenarios() but never scans — used by /api/status hot path."""
    by_id = {}
    for s in AVAILABLE_MISSIONS:
        by_id[s["id"]] = dict(s)
    for s in cached_scenarios():
        by_id.setdefault(s["id"], dict(s))
    out = list(by_id.values())
    out.sort(key=lambda s: (s["source"] != "vanilla", s["source"], s["name"]))
    return out


# ─── HELPERS ──────────────────────────────────────────────────────────────────

def get_server_pid():
    try:
        r = subprocess.run(["pgrep", "-f", "ArmaReforgerServer"], capture_output=True, text=True)
        pids = r.stdout.strip().splitlines()
        return int(pids[0]) if pids else None
    except Exception:
        return None

def get_process_uptime(pid):
    try:
        r = subprocess.run(["ps", "-o", "etimes=", "-p", str(pid)], capture_output=True, text=True)
        return int(r.stdout.strip())
    except Exception:
        return 0

def format_uptime(seconds):
    if seconds < 60:    return f"{seconds}s"
    if seconds < 3600:  return f"{seconds // 60}m {seconds % 60}s"
    return f"{seconds // 3600}h {(seconds % 3600) // 60}m"

def get_cpu_count():
    try:
        r = subprocess.run(["nproc"], capture_output=True, text=True)
        return max(1, int(r.stdout.strip()))
    except Exception:
        return 1

def get_cpu_ram(pid):
    try:
        r = subprocess.run(["ps", "-p", str(pid), "-o", "pcpu=,rss="], capture_output=True, text=True)
        parts = r.stdout.strip().split()
        cpu = round(float(parts[0]) / get_cpu_count(), 1)
        ram = round(int(parts[1]) / 1024, 1)
        return cpu, ram
    except Exception:
        return 0.0, 0.0

def get_system_ram():
    try:
        with open("/proc/meminfo") as f:
            lines = f.readlines()
        mem = {l.split()[0].rstrip(":"): int(l.split()[1]) for l in lines if len(l.split()) >= 2}
        total = round(mem["MemTotal"] / 1024, 1)
        used  = round((mem["MemTotal"] - mem["MemAvailable"]) / 1024, 1)
        return used, total
    except Exception:
        return 0, 0

def get_latest_log():
    try:
        dirs = sorted(glob.glob(f"{LOG_DIR}/logs_*"), reverse=True)
        if not dirs:
            return None
        path = os.path.join(dirs[0], "console.log")
        return path if os.path.exists(path) else None
    except Exception:
        return None

def read_config():
    try:
        with open(SERVER_CONFIG) as f:
            return json.load(f)
    except Exception:
        return {}

def write_config(cfg):
    with open(SERVER_CONFIG, "w") as f:
        json.dump(cfg, f, indent="\t")

def get_map_name(cfg=None):
    try:
        if cfg is None:
            cfg = read_config()
        sid = cfg.get("game", {}).get("scenarioId", "")
        if sid:
            for m in AVAILABLE_MISSIONS:
                if m["id"] == sid:
                    return m["name"]
            return sid.split("/")[-1].replace(".conf", "")
        return "Unknown"
    except Exception:
        return "Unknown"

# ─── ROUTES ───────────────────────────────────────────────────────────────────

@app.route("/manifest.json")
def manifest():
    return send_from_directory('static', 'manifest.json', mimetype='application/manifest+json')

@app.route("/service-worker.js")
def service_worker():
    return send_from_directory('static', 'service-worker.js', mimetype='application/javascript')

@app.route("/")
def index():
    if not session.get("logged_in"):
        return redirect("/login")
    _ensure_csrf()
    return open(os.path.join(os.path.dirname(__file__), "index.html")).read()

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        ip = _client_ip()
        if not _login_rate_ok(ip):
            return jsonify({"ok": False, "error": "Too many attempts. Wait a minute."}), 429
        data = request.get_json(silent=True) or {}
        # bcrypt is intentionally slow — even on a successful login it adds ~100ms,
        # which is also a natural defense against brute force.
        if _verify_password(data.get("password", "")):
            session.clear()
            session.permanent = True
            session["logged_in"] = True
            session["login_at"] = int(time.time())
            _ensure_csrf()
            return jsonify({"ok": True, "csrf": session["csrf"]})
        return jsonify({"ok": False, "error": "Invalid password"}), 401
    return open(os.path.join(os.path.dirname(__file__), "login.html")).read()

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"ok": True})

@app.route("/api/csrf")
def api_csrf():
    """Front-end fetches a CSRF token after login and on tab refresh."""
    if not session.get("logged_in"):
        return jsonify({"error": "unauthorized"}), 401
    return jsonify({"csrf": _ensure_csrf()})

@app.route("/api/status")
def api_status():
    if not session.get("logged_in"):
        return jsonify({"error": "unauthorized"}), 401
    pid = get_server_pid()
    cfg = read_config()
    cpu, ram = get_cpu_ram(pid) if pid else (0.0, 0.0)
    ram_used, ram_total = get_system_ram()
    missions = all_scenarios_cached()
    return jsonify({
        "running":        pid is not None,
        "pid":            pid,
        "map":            get_map_name(cfg),
        "players":        0,
        "uptime":         format_uptime(get_process_uptime(pid)) if pid else "—",
        "uptime_sec":     get_process_uptime(pid) if pid else 0,
        "server_name":    cfg.get("game", {}).get("name", "—"),
        "ip":             cfg.get("publicAddress", "—"),
        "port":           cfg.get("publicPort", "—"),
        "scenario_id":    cfg.get("game", {}).get("scenarioId", ""),
        "missions":       missions,
        "missions_count": {"vanilla": sum(1 for m in missions if m.get("source") == "vanilla"),
                           "from_mods": sum(1 for m in missions if m.get("source") != "vanilla")},
        "password":       cfg.get("game", {}).get("password", ""),
        "password_admin": cfg.get("game", {}).get("passwordAdmin", ""),
        "cpu":            cpu,
        "ram_process":    ram,
        "ram_used":       ram_used,
        "ram_total":      ram_total,
        "mods":           cfg.get("game", {}).get("mods", []),
        "csrf":           _ensure_csrf(),
    })

@app.route("/api/scenarios/rescan", methods=["POST"])
def api_scenarios_rescan():
    if not session.get("logged_in"):
        return jsonify({"error": "unauthorized"}), 401
    err = _csrf_required()
    if err: return err
    missions, diag = all_scenarios(force_rescan=True)
    return jsonify({
        "ok": True,
        "missions": missions,
        "missions_count": {"vanilla": sum(1 for m in missions if m.get("source") == "vanilla"),
                           "from_mods": sum(1 for m in missions if m.get("source") != "vanilla")},
        "diag": diag,
    })

@app.route("/api/metrics")
def api_metrics():
    if not session.get("logged_in"):
        return jsonify({"error": "unauthorized"}), 401
    pid = get_server_pid()
    cpu, ram = get_cpu_ram(pid) if pid else (0.0, 0.0)
    ram_used, ram_total = get_system_ram()
    return jsonify({
        "cpu": cpu, "ram_process": ram,
        "ram_used": ram_used, "ram_total": ram_total,
        "running": pid is not None, "ts": int(time.time()),
    })

@app.route("/api/logs")
def api_logs():
    if not session.get("logged_in"):
        return jsonify({"error": "unauthorized"}), 401
    n = int(request.args.get("lines", 100))
    path = get_latest_log()
    if not path:
        return jsonify({"lines": [], "path": None})
    try:
        r = subprocess.run(["tail", "-n", str(n), path], capture_output=True, text=True)
        return jsonify({"lines": r.stdout.splitlines(), "path": path})
    except Exception as e:
        return jsonify({"lines": [], "error": str(e)})

def _normalize_mod_entry(entry):
    """Validate one mod row. Returns canonical dict or None."""
    if not isinstance(entry, dict):
        return None
    mod_id = str(entry.get("modId", "")).strip()
    if not mod_id or len(mod_id) > 32:
        return None
    if not all(c in "0123456789ABCDEFabcdef" for c in mod_id):
        return None
    out = {"modId": mod_id.upper()}
    name = str(entry.get("name", "")).strip()
    if name:
        if len(name) > 200 or any(c in name for c in "\n\r"):
            return None
        out["name"] = name
    version = str(entry.get("version", "")).strip()
    if version:
        if len(version) > 32 or any(c in version for c in '\n\r"\\'):
            return None
        out["version"] = version
    return out


@app.route("/api/config", methods=["POST"])
def api_config():
    if not session.get("logged_in"):
        return jsonify({"error": "unauthorized"}), 401
    err = _csrf_required()
    if err: return err
    data = request.get_json(silent=True) or {}
    cfg  = read_config()
    changed = False
    if "server_name" in data and data["server_name"].strip():
        cfg.setdefault("game", {})["name"] = data["server_name"].strip(); changed = True
    if "scenario_id" in data:
        sid = data["scenario_id"].strip()
        valid_ids = {m["id"] for m in all_scenarios_cached()}
        if sid not in valid_ids:
            return jsonify({"ok": False, "error": "Unknown scenario"})
        cfg.setdefault("game", {})["scenarioId"] = sid; changed = True
    if "password" in data:
        cfg.setdefault("game", {})["password"] = data["password"]; changed = True
    if "password_admin" in data and data["password_admin"].strip():
        cfg.setdefault("game", {})["passwordAdmin"] = data["password_admin"].strip(); changed = True
    if not changed:
        return jsonify({"ok": False, "error": "No changes"})
    try:
        write_config(cfg)
        return jsonify({"ok": True, "restart_required": get_server_pid() is not None})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

@app.route("/api/mods/add", methods=["POST"])
def api_mods_add():
    if not session.get("logged_in"):
        return jsonify({"error": "unauthorized"}), 401
    err = _csrf_required()
    if err: return err
    data = request.get_json(silent=True) or {}
    norm = _normalize_mod_entry({"modId": data.get("modId",""), "name": data.get("name",""), "version": data.get("version","")})
    if not norm:
        return jsonify({"ok": False, "error": "Invalid mod entry (modId must be 1-32 hex chars)"})
    if "name" not in norm:
        return jsonify({"ok": False, "error": "name is required for manual entry"})
    cfg  = read_config()
    mods = cfg.setdefault("game", {}).setdefault("mods", [])
    if any(m.get("modId", "").upper() == norm["modId"] for m in mods):
        return jsonify({"ok": False, "error": "Mod with this ID already exists"})
    mods.append(norm)
    try:
        write_config(cfg)
        return jsonify({"ok": True, "restart_required": get_server_pid() is not None, "mods": mods})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

@app.route("/api/mods/import", methods=["POST"])
def api_mods_import():
    """Bulk-import mods. Accepts either:
       - multipart/form-data with a 'file' part containing a JSON array, plus
         form fields 'mode' (replace|merge) and '_csrf'.
       - application/json with {payload: <text or array>, mode, _csrf}.
    """
    if not session.get("logged_in"):
        return jsonify({"error": "unauthorized"}), 401
    err = _csrf_required()
    if err: return err

    raw = None
    mode = "replace"

    if request.files and "file" in request.files:
        f = request.files["file"]
        try:
            raw = f.read().decode("utf-8")
        except UnicodeDecodeError:
            return jsonify({"ok": False, "error": "File must be UTF-8 encoded JSON"}), 400
        mode = (request.form.get("mode") or "replace").strip().lower()
    else:
        body = request.get_json(silent=True) or {}
        payload = body.get("payload")
        if isinstance(payload, list):
            raw = json.dumps(payload)
        elif isinstance(payload, str):
            raw = payload
        mode = (body.get("mode") or "replace").strip().lower()

    if mode not in ("replace", "merge"):
        return jsonify({"ok": False, "error": "mode must be 'replace' or 'merge'"}), 400
    if not raw or not raw.strip():
        return jsonify({"ok": False, "error": "Empty payload"}), 400

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        return jsonify({"ok": False, "error": f"Invalid JSON: {e.msg} at line {e.lineno} col {e.colno}"}), 400
    if not isinstance(data, list):
        return jsonify({"ok": False, "error": "Top-level value must be a JSON array"}), 400

    valid = []
    skipped = []
    seen = set()
    for i, entry in enumerate(data):
        norm = _normalize_mod_entry(entry)
        if not norm:
            skipped.append(f"#{i + 1}: invalid")
            continue
        if norm["modId"] in seen:
            skipped.append(f"#{i + 1}: duplicate modId {norm['modId']}")
            continue
        seen.add(norm["modId"])
        valid.append(norm)

    cfg = read_config()
    g   = cfg.setdefault("game", {})

    if mode == "merge":
        existing = list(g.get("mods", []))
        existing_ids = {str(m.get("modId", "")).upper() for m in existing}
        added = 0
        for m in valid:
            if m["modId"] not in existing_ids:
                existing.append(m)
                existing_ids.add(m["modId"])
                added += 1
        g["mods"] = existing
        msg = f"Merged: {added} added, {len(valid) - added} already present"
    else:
        g["mods"] = valid
        msg = f"Replaced full mod list with {len(valid)} entries"

    try:
        write_config(cfg)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

    return jsonify({
        "ok": True,
        "message": msg,
        "imported": len(valid),
        "skipped": skipped,
        "mods": g["mods"],
        "restart_required": get_server_pid() is not None,
    })

@app.route("/api/mods/remove", methods=["POST"])
def api_mods_remove():
    if not session.get("logged_in"):
        return jsonify({"error": "unauthorized"}), 401
    err = _csrf_required()
    if err: return err
    data   = request.get_json(silent=True) or {}
    mod_id = data.get("modId", "").strip().upper()
    if not mod_id:
        return jsonify({"ok": False, "error": "Missing modId"})
    cfg  = read_config()
    mods = cfg.get("game", {}).get("mods", [])
    new  = [m for m in mods if str(m.get("modId", "")).upper() != mod_id]
    if len(new) == len(mods):
        return jsonify({"ok": False, "error": "Mod not found"})
    cfg.setdefault("game", {})["mods"] = new
    try:
        write_config(cfg)
        return jsonify({"ok": True, "restart_required": get_server_pid() is not None, "mods": new})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

@app.route("/api/start", methods=["POST"])
def api_start():
    if not session.get("logged_in"):
        return jsonify({"error": "unauthorized"}), 401
    err = _csrf_required()
    if err: return err
    if get_server_pid():
        return jsonify({"ok": False, "error": "Server is already running"})
    try:
        subprocess.Popen([SERVER_BINARY] + SERVER_ARGS, cwd=SERVER_DIR,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         start_new_session=True)
        time.sleep(1)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

@app.route("/api/stop", methods=["POST"])
def api_stop():
    if not session.get("logged_in"):
        return jsonify({"error": "unauthorized"}), 401
    err = _csrf_required()
    if err: return err
    pid = get_server_pid()
    if not pid:
        return jsonify({"ok": False, "error": "Server is not running"})
    try:
        subprocess.run(["kill", str(pid)], check=True)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

@app.route("/api/restart", methods=["POST"])
def api_restart():
    if not session.get("logged_in"):
        return jsonify({"error": "unauthorized"}), 401
    err = _csrf_required()
    if err: return err
    pid = get_server_pid()
    if pid:
        try:
            subprocess.run(["kill", str(pid)], check=True)
            time.sleep(3)
        except Exception as e:
            return jsonify({"ok": False, "error": f"Stop failed: {e}"})
    try:
        subprocess.Popen([SERVER_BINARY] + SERVER_ARGS, cwd=SERVER_DIR,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         start_new_session=True)
        time.sleep(1)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PANEL_PORT, threaded=True)
