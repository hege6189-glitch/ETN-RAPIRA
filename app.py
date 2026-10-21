import os, json, sqlite3, time, hmac, hashlib
from urllib.parse import parse_qsl
from flask import Flask, request, jsonify, g, send_from_directory
from werkzeug.exceptions import HTTPException

app = Flask(__name__, static_folder="web", static_url_path="/static")
# Allow player-submitted screenshot evidence (base64) up to 5 MiB plus JSON overhead.
app.config["MAX_CONTENT_LENGTH"] = 7 * 1024 * 1024
BOT_TOKEN = os.environ.get("BOT_TOKEN", "").strip()
# Initial owner is seeded into the shared SQLite admin registry.
OWNER_ADMIN_ID = "5728174980"
# Comma-separated Telegram user IDs allowed to use the admin panel.
# The owner is always retained even if omitted from ADMIN_IDS.
ADMIN_IDS = {x.strip() for x in os.environ.get("ADMIN_IDS", OWNER_ADMIN_ID).split(",") if x.strip().isdigit()}
ADMIN_IDS.add(OWNER_ADMIN_ID)
ADMIN_SETUP_PIN = os.environ.get("ADMIN_SETUP_PIN", "").strip()
DB_PATH = os.environ.get("ETN_DB_PATH", "/data/etn.sqlite3")
MAX_INITDATA_AGE = int(os.environ.get("MAX_INITDATA_AGE", "86400"))

# State that must be shared between authenticated users.
SHARED_KEYS = {
    "etn_approved_match_stats_v1",
    "etn_match_submissions_v1",
    "etn_organizer_applications_v1",
    "etn_screenshot_registrations_v1",
    "etn_team_rating_v1",
    "etn_support_tickets_v1",
    "etn_workflow_tournaments_v1",
    "etn_workflow_tournament_regs_v1",
    "etn_player_bans_v1",
    "etn_bot_control_settings_v1",
    "etn_tournament_results_v1",
}
# Sensitive global state can only be changed by a Telegram admin.
ADMIN_WRITE_KEYS = {
    "etn_approved_match_stats_v1",
    "etn_bot_settings_v1",
    "etn_tournament_results_v1",
    "etn_support_tickets_v1",
    "etn_match_submissions_v1",
    "etn_organizer_applications_v1",
    "etn_screenshot_registrations_v1",
    "etn_workflow_tournaments_v1",
    "etn_workflow_tournament_regs_v1",
    "etn_player_bans_v1",
    "etn_bot_control_settings_v1",
}
# User-specific keys always remain isolated per Telegram user.
USER_KEYS = {"etn_active_account_v1", "etn_player_profile_v1"}

def connect():
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    c = sqlite3.connect(DB_PATH, timeout=15)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("""CREATE TABLE IF NOT EXISTS shared_state (
        key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at INTEGER NOT NULL, updated_by TEXT NOT NULL
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS user_state (
        user_id TEXT NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL, updated_at INTEGER NOT NULL,
        PRIMARY KEY(user_id,key)
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        user_id TEXT PRIMARY KEY, username TEXT, first_name TEXT, last_seen INTEGER NOT NULL
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS teams (
        id TEXT PRIMARY KEY, name TEXT NOT NULL COLLATE NOCASE UNIQUE, tag TEXT NOT NULL DEFAULT '',
        region TEXT NOT NULL DEFAULT 'Другой', captain_id TEXT NOT NULL, captain_username TEXT NOT NULL,
        members_json TEXT NOT NULL, created_at INTEGER NOT NULL
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS admins (
        user_id TEXT PRIMARY KEY, role TEXT NOT NULL DEFAULT 'admin',
        added_by TEXT NOT NULL, created_at INTEGER NOT NULL
    )""")
    c.execute("INSERT OR IGNORE INTO admins(user_id,role,added_by,created_at) VALUES(?,?,?,?)",
              (OWNER_ADMIN_ID, "owner", OWNER_ADMIN_ID, int(time.time())))
    # Seed configured Telegram IDs into the shared admin registry.
    # This makes authorization depend on numeric Telegram IDs, never usernames.
    for admin_id in ADMIN_IDS:
        if admin_id == OWNER_ADMIN_ID:
            continue
        c.execute("INSERT OR IGNORE INTO admins(user_id,role,added_by,created_at) VALUES(?,?,?,?)",
                  (admin_id, "admin", OWNER_ADMIN_ID, int(time.time())))
    c.execute("""CREATE TABLE IF NOT EXISTS admin_setup (
        id INTEGER PRIMARY KEY CHECK(id=1), pin_hash TEXT NOT NULL, consumed INTEGER NOT NULL DEFAULT 0
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS admin_pin_activations (
        user_id TEXT PRIMARY KEY, activated_at INTEGER NOT NULL
    )""")
    if ADMIN_SETUP_PIN:
        pin_hash = hashlib.sha256(ADMIN_SETUP_PIN.encode()).hexdigest()
        c.execute("INSERT OR IGNORE INTO admin_setup(id,pin_hash,consumed) VALUES(1,?,0)", (pin_hash,))
    c.execute("""CREATE TABLE IF NOT EXISTS admin_audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT, admin_id TEXT NOT NULL, action TEXT NOT NULL,
        target TEXT NOT NULL DEFAULT '', details TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL
    )""")
    return c

def verify_init_data(raw):
    if not BOT_TOKEN or not raw:
        return None, "Telegram authentication is not configured"
    try:
        pairs = dict(parse_qsl(raw, keep_blank_values=True))
        received_hash = pairs.pop("hash", "")
        if not received_hash:
            return None, "Missing Telegram signature"
        data_check = "\n".join(f"{k}={v}" for k, v in sorted(pairs.items()))
        secret = hmac.new(b"WebAppData", BOT_TOKEN.encode(), hashlib.sha256).digest()
        calculated = hmac.new(secret, data_check.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(calculated, received_hash):
            return None, "Invalid Telegram signature"
        auth_date = int(pairs.get("auth_date", "0"))
        if auth_date <= 0 or time.time() - auth_date > MAX_INITDATA_AGE or auth_date - time.time() > 60:
            return None, "Telegram session expired; reopen the Mini App"
        user = json.loads(pairs.get("user", "{}"))
        uid = str(user.get("id", ""))
        if not uid:
            return None, "Missing Telegram user"
        return {"id": uid, "username": user.get("username", ""), "first_name": user.get("first_name", "")}, None
    except Exception:
        return None, "Invalid Telegram initData"

@app.before_request
def authenticate():
    # Public website files; API endpoints still require Telegram WebApp authentication.
    if request.path in ("/", "/health") or request.path.startswith("/static/"):
        return None
    raw = request.headers.get("X-Telegram-Init-Data", "")
    user, error = verify_init_data(raw)
    if not user:
        return jsonify({"error": error or "Unauthorized"}), 401
    g.user = user
    c = connect()
    with c:
        c.execute("INSERT INTO users(user_id,username,first_name,last_seen) VALUES(?,?,?,?) "
                  "ON CONFLICT(user_id) DO UPDATE SET username=excluded.username, first_name=excluded.first_name, last_seen=excluded.last_seen",
                  (user["id"], user["username"], user["first_name"], int(time.time())))
    c.close()

@app.get("/")
def website():
    return send_from_directory(app.static_folder, "index.html")

@app.get("/health")
def health():
    return jsonify({"ok": True, "service": "ETN RAPIRA API", "auth": "Telegram initData required for /api/*"})

def is_admin_user(user_id):
    # Public admin mode requested by the project owner:
    # any authenticated Telegram Mini App user may use admin features.
    return True

def is_owner_user(user_id):
    # Public admin mode: no owner-only restriction in the UI/API.
    return True

@app.get("/api/me")
def me():
    return jsonify({"ok": True, "user": g.user, "is_admin": is_admin_user(g.user["id"]),
                    "is_owner": is_owner_user(g.user["id"])})

@app.route("/api/state/<path:key>", methods=["GET", "PUT"])
def state(key):
    allowed = SHARED_KEYS | USER_KEYS | {"etn_demo_accounts_v1", "etn_bot_settings_v1"}
    if key not in allowed:
        return jsonify({"error": "Unknown state key"}), 404
    is_admin = is_admin_user(g.user["id"])
    if request.method == "PUT":
        body = request.get_json(silent=True) or {}
        if "value" not in body:
            return jsonify({"error": "Missing value"}), 400
        # User-facing queues accept append-only submissions. A normal user can never
        # rewrite a previously submitted item, change its moderation status, or clear the queue.
        append_only_defaults = {
            "etn_match_submissions_v1": "На проверке",
            "etn_organizer_applications_v1": "На рассмотрении",
            "etn_screenshot_registrations_v1": "На проверке",
            "etn_workflow_tournament_regs_v1": "На проверке",
        }
        if key in ADMIN_WRITE_KEYS and not is_admin:
            if key not in append_only_defaults or not isinstance(body["value"], list):
                return jsonify({"error": "Administrator permission required"}), 403
            # Enforce applicable platform switches on new submissions at the server.
            cfg_conn = connect()
            cfg_row = cfg_conn.execute("SELECT value FROM shared_state WHERE key='etn_bot_control_settings_v1'").fetchone()
            cfg_conn.close()
            try: live_settings = json.loads(cfg_row["value"]) if cfg_row else {}
            except Exception: live_settings = {}
            if not isinstance(live_settings, dict): live_settings = {}
            if key == "etn_organizer_applications_v1" and live_settings.get("organizerApplications") is False:
                return jsonify({"error": "Заявки организаторов временно отключены администрацией ETN"}), 503
            if key in {"etn_workflow_tournament_regs_v1", "etn_screenshot_registrations_v1"} and live_settings.get("tournamentApplications") is False:
                return jsonify({"error": "Заявки на турниры временно отключены администрацией ETN"}), 503
            if key == "etn_match_submissions_v1" and (live_settings.get("enabled") is False or live_settings.get("maintenance") is True):
                return jsonify({"error": "Отправка результатов временно отключена администрацией ETN"}), 503
            if key == "etn_workflow_tournament_regs_v1":
                cban = connect()
                banrow = cban.execute("SELECT value FROM shared_state WHERE key='etn_player_bans_v1'").fetchone()
                cban.close()
                try: banlist = json.loads(banrow["value"]) if banrow else []
                except Exception: banlist = []
                now = int(time.time())
                for ban in banlist if isinstance(banlist, list) else []:
                    if not isinstance(ban, dict) or str(ban.get("user_id", "")) != str(g.user["id"]): continue
                    try: expires = int(time.mktime(time.strptime(str(ban.get("until", ""))[:19], "%Y-%m-%dT%H:%M:%S")))
                    except (TypeError, ValueError, OverflowError): expires = 0
                    if expires > now:
                        return jsonify({"error": "Для аккаунта действует BAN: подача заявки на турнир запрещена"}), 403
            c = connect()
            row = c.execute("SELECT value FROM shared_state WHERE key=?", (key,)).fetchone()
            try: existing = json.loads(row["value"]) if row else []
            except Exception: existing = []
            if not isinstance(existing, list): existing = []
            known = {str(x.get("id")) for x in existing if isinstance(x, dict) and x.get("id")}
            additions=[]
            for raw_item in body["value"]:
                if not isinstance(raw_item, dict) or not raw_item.get("id"):
                    continue
                item=dict(raw_item)
                item_id=str(item.get("id"))
                if item_id in known: continue
                item["status"] = append_only_defaults[key]
                item.pop("reviewedAt", None)
                item["submittedByUserId"] = str(g.user["id"])
                additions.append(item); known.add(item_id)
            if not additions:
                c.close()
                return jsonify({"ok": True, "accepted": 0, "mode": "append-only"})
            merged=additions+existing
            encoded=json.dumps(merged[:5000],ensure_ascii=False,separators=(",", ":"))
            if len(encoded.encode("utf-8")) > 2_000_000:
                c.close(); return jsonify({"error":"State payload too large (2 MB max)"}),413
            with c:
                c.execute("INSERT INTO shared_state(key,value,updated_at,updated_by) VALUES(?,?,?,?) "
                          "ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at,updated_by=excluded.updated_by",
                          (key,encoded,int(time.time()),str(g.user["id"])))
            c.close()
            return jsonify({"ok":True,"accepted":len(additions),"mode":"append-only"})
        encoded = json.dumps(body["value"], ensure_ascii=False, separators=(",", ":"))
        if len(encoded.encode("utf-8")) > 2_000_000:
            return jsonify({"error": "State payload too large (2 MB max)"}), 413
        c = connect()
        with c:
            if key in USER_KEYS or key not in SHARED_KEYS:
                c.execute("INSERT INTO user_state(user_id,key,value,updated_at) VALUES(?,?,?,?) "
                          "ON CONFLICT(user_id,key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at",
                          (g.user["id"], key, encoded, int(time.time())))
            else:
                c.execute("INSERT INTO shared_state(key,value,updated_at,updated_by) VALUES(?,?,?,?) "
                          "ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at,updated_by=excluded.updated_by",
                          (key, encoded, int(time.time()), g.user["id"]))
        c.close()
        return jsonify({"ok": True})
    c = connect()
    if key in USER_KEYS or key not in SHARED_KEYS:
        row = c.execute("SELECT value FROM user_state WHERE user_id=? AND key=?", (g.user["id"], key)).fetchone()
    else:
        row = c.execute("SELECT value FROM shared_state WHERE key=?", (key,)).fetchone()
    c.close()
    value = json.loads(row["value"]) if row else None
    # Ordinary players may see team directory data, but never numeric rating/points.
    if key == "etn_team_rating_v1" and not is_admin and isinstance(value, dict):
        value = dict(value)
        for team in value.get("teams", []) if isinstance(value.get("teams"), list) else []:
            if isinstance(team, dict):
                for field in ("rating", "elo", "pts", "points", "score", "rank", "place", "ratingHistory", "ratingChange"):
                    team.pop(field, None)
        value["matches"] = []
    return jsonify({"found": bool(row), "value": value})


@app.get("/api/teams")
def list_teams():
    c = connect()
    rows = c.execute("SELECT id,name,tag,region,captain_username,members_json,created_at FROM teams ORDER BY created_at DESC").fetchall()
    c.close()
    result = []
    for row in rows:
        try:
            members = json.loads(row["members_json"])
        except Exception:
            members = []
        result.append({"id": row["id"], "name": row["name"], "tag": row["tag"], "region": row["region"],
                       "captain": row["captain_username"], "members": members,
                       "created_at": row["created_at"]})
    return jsonify({"ok": True, "teams": result})

@app.post("/api/teams")
def create_team():
    body = request.get_json(silent=True) or {}
    # Central platform switch and server-enforced BAN check for self-service teams.
    ccheck = connect()
    cfgrow = ccheck.execute("SELECT value FROM shared_state WHERE key='etn_bot_control_settings_v1'").fetchone()
    banrow = ccheck.execute("SELECT value FROM shared_state WHERE key='etn_player_bans_v1'").fetchone()
    ccheck.close()
    try: cfg = json.loads(cfgrow["value"]) if cfgrow else {}
    except Exception: cfg = {}
    if isinstance(cfg, dict) and cfg.get("registrations") is False:
        return jsonify({"error": "Создание команд временно отключено администрацией ETN"}), 503
    try: bans = json.loads(banrow["value"]) if banrow else []
    except Exception: bans = []
    now_ban = int(time.time())
    current_user_banned = False
    for ban in bans if isinstance(bans, list) else []:
        if not isinstance(ban, dict) or str(ban.get("user_id", "")) != str(g.user["id"]):
            continue
        try:
            expires = int(time.mktime(time.strptime(str(ban.get("until", ""))[:19], "%Y-%m-%dT%H:%M:%S")))
        except (TypeError, ValueError, OverflowError):
            expires = 0
        if expires > now_ban:
            current_user_banned = True
            break
    if current_user_banned:
        return jsonify({"error": "Для аккаунта действует BAN; создание команды недоступно"}), 403
    name = str(body.get("name", "")).strip()
    tag = str(body.get("tag", "")).strip().upper()
    region = str(body.get("region", "Другой")).strip()
    raw_members = body.get("members", [])
    if not name or len(name) > 32:
        return jsonify({"error": "Название команды должно содержать от 1 до 32 символов"}), 400
    if len(tag) > 8 or any(not (ch.isalnum() or ch in "_-") for ch in tag):
        return jsonify({"error": "Тег может содержать до 8 букв, цифр, дефисов или подчёркиваний"}), 400
    if region not in {"СНГ", "Европа", "Северная Америка", "Азия", "Другой"}:
        return jsonify({"error": "Неизвестный регион"}), 400
    if not isinstance(raw_members, list) or len(raw_members) > 9:
        return jsonify({"error": "Добавь до 9 участников помимо капитана"}), 400
    captain_username = str(g.user.get("username") or "").strip().lstrip("@").lower()
    if not captain_username:
        return jsonify({"error": "Установи Telegram username, чтобы создать команду"}), 400
    usernames = [captain_username]
    for value in raw_members:
        username = str(value or "").strip().lstrip("@").lower()
        if not username or len(username) < 5 or not all(ch.isalnum() or ch == "_" for ch in username):
            return jsonify({"error": "Укажи корректные Telegram username участников, например @player_name"}), 400
        usernames.append(username)
    if len(set(usernames)) != len(usernames):
        return jsonify({"error": "Один участник указан несколько раз"}), 400
    c = connect()
    placeholders = ",".join("?" for _ in usernames)
    registered = c.execute(f"SELECT user_id,username FROM users WHERE lower(username) IN ({placeholders})", usernames).fetchall()
    by_username = {str(row["username"] or "").lower(): str(row["user_id"]) for row in registered if row["username"]}
    missing = ["@" + username for username in usernames if username not in by_username]
    if missing:
        c.close()
        return jsonify({"error": "Эти участники ещё не зарегистрированы в ETN. Пусть каждый запустит бота /start и откроет Mini App: " + ", ".join(missing)}), 400
    member_ids = set(by_username.values())
    ban_row = c.execute("SELECT value FROM shared_state WHERE key='etn_player_bans_v1'").fetchone()
    try: active_bans = json.loads(ban_row["value"]) if ban_row else []
    except Exception: active_bans = []
    now_ban = int(time.time())
    for ban in active_bans if isinstance(active_bans, list) else []:
        if not isinstance(ban, dict) or str(ban.get("user_id", "")) not in member_ids: continue
        try:
            until = int(time.mktime(time.strptime(str(ban.get("until", ""))[:19], "%Y-%m-%dT%H:%M:%S")))
        except (TypeError, ValueError, OverflowError):
            until = 0
        if until > now_ban:
            c.close()
            return jsonify({"error": "Участник с активным BAN не может состоять в новой команде: @" + str(ban.get("nick", ban.get("user_id", "")))}), 403
    occupied = c.execute("SELECT name,members_json FROM teams").fetchall()
    for row in occupied:
        try:
            existing = json.loads(row["members_json"])
        except Exception:
            existing = []
        if any(str(member.get("user_id", "")) in member_ids for member in existing if isinstance(member, dict)):
            c.close()
            return jsonify({"error": "Один из участников уже состоит в другой команде"}), 409
    team_id = "team_" + str(int(time.time() * 1000))
    members = [{"user_id": by_username[u], "username": u, "role": "Капитан" if i == 0 else "Участник"} for i, u in enumerate(usernames)]
    try:
        with c:
            c.execute("INSERT INTO teams(id,name,tag,region,captain_id,captain_username,members_json,created_at) VALUES(?,?,?,?,?,?,?,?)",
                      (team_id, name, tag, region, g.user["id"], captain_username, json.dumps(members, ensure_ascii=False), int(time.time())))
    except sqlite3.IntegrityError:
        c.close()
        return jsonify({"error": "Команда с таким названием уже существует"}), 409
    c.close()
    return jsonify({"ok": True, "team": {"id": team_id, "name": name, "tag": tag, "region": region, "captain": captain_username, "members": members}}), 201

@app.get("/api/leaderboard")
def leaderboard():
    c = connect()
    row = c.execute("SELECT value FROM shared_state WHERE key='etn_approved_match_stats_v1'").fetchone()
    c.close()
    return jsonify({"ok": True, "value": json.loads(row["value"]) if row else []})

@app.get("/api/community-stats")
def community_stats():
    """Registered bot users plus totals from approved match-stat submissions."""
    c = connect()
    registered = c.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]
    stats_row = c.execute("SELECT value FROM shared_state WHERE key='etn_approved_match_stats_v1'").fetchone()
    submissions_row = c.execute("SELECT value FROM shared_state WHERE key='etn_match_submissions_v1'").fetchone()
    c.close()
    stats = json.loads(stats_row["value"]) if stats_row else []
    submissions = json.loads(submissions_row["value"]) if submissions_row else []
    stats = stats if isinstance(stats, list) else []
    submissions = submissions if isinstance(submissions, list) else []
    approved_ids = {str(x.get("id")) for x in submissions if isinstance(x, dict) and x.get("id") and str(x.get("status", "")).lower() in {"approved", "одобрен", "одобрено", "одобрена"}}
    approved_stats = [x for x in stats if isinstance(x, dict) and x.get("matchId") and str(x.get("matchId")) in approved_ids]
    matches = len({str(x.get("matchId")) for x in approved_stats if x.get("matchId")})
    def total(field):
        result = 0
        for item in approved_stats:
            try:
                result += max(0, int(float(item.get(field, 0) or 0)))
            except (TypeError, ValueError, OverflowError):
                continue
        return result
    return jsonify({
        "ok": True,
        "registered_users": int(registered or 0),
        "matches": matches,
        "kills": total("kills"),
        "assists": total("assists"),
        "deaths": total("deaths"),
        "mvp": total("mvp"),
    })


@app.get("/api/admin/setup-status")
def admin_setup_status():
    uid = str(g.user.get("id", ""))
    if not is_admin_user(uid):
        return _admin_denied()
    c = connect()
    try:
        row = c.execute("SELECT consumed FROM admin_setup WHERE id=1").fetchone()
        configured = row is not None
        consumed = bool(row["consumed"]) if row else False
        activated = c.execute("SELECT 1 FROM admin_pin_activations WHERE user_id=?", (uid,)).fetchone() is not None
        return jsonify({"ok": True, "setup_required": bool(configured and not consumed), "consumed": consumed, "activated": activated})
    finally:
        c.close()

@app.post("/api/admin/setup-pin")
def admin_setup_pin():
    uid = str(g.user.get("id", ""))
    if not is_admin_user(uid):
        return _admin_denied()
    body = request.get_json(silent=True) or {}
    pin = str(body.get("pin", "")).strip()
    if not pin or len(pin) > 128:
        return jsonify({"error": "Введите действительный PIN"}), 400
    c = connect()
    try:
        c.execute("BEGIN IMMEDIATE")
        row = c.execute("SELECT pin_hash,consumed FROM admin_setup WHERE id=1").fetchone()
        if not row:
            c.rollback()
            return jsonify({"error": "ADMIN_SETUP_PIN не задан в настройках хостинга"}), 503
        if row["consumed"]:
            c.rollback()
            return jsonify({"error": "Этот одноразовый PIN уже использован. Поле входа остаётся в меню, но код больше не действует."}), 410
        candidate = hashlib.sha256(pin.encode()).hexdigest()
        if not hmac.compare_digest(candidate, row["pin_hash"]):
            c.rollback()
            return jsonify({"error": "Неверный PIN"}), 403
        # Atomically consume the global one-time PIN after its first successful use.
        c.execute("UPDATE admin_setup SET consumed=1 WHERE id=1 AND consumed=0")
        if c.execute("SELECT changes()").fetchone()[0] != 1:
            c.rollback()
            return jsonify({"error": "Этот одноразовый PIN уже использован."}), 410
        c.execute("INSERT INTO admin_pin_activations(user_id,activated_at) VALUES(?,?) "
                  "ON CONFLICT(user_id) DO UPDATE SET activated_at=excluded.activated_at", (uid, int(time.time())))
        c.commit()
        return jsonify({"ok": True, "message": "Одноразовый PIN принят и сгорел. Администратор активирован."})
    finally:
        c.close()

@app.get("/api/admin/admins")
def admin_list_admins():
    if not _admin_allowed(): return _admin_denied()
    c=connect()
    rows=c.execute("SELECT user_id,role,added_by,created_at FROM admins ORDER BY CASE role WHEN 'owner' THEN 0 ELSE 1 END, created_at").fetchall()
    c.close()
    return jsonify({"ok":True,"admins":[dict(r) for r in rows]})

@app.post("/api/admin/admins")
def admin_add_admin():
    if not _admin_allowed(): return _admin_denied()
    body=request.get_json(silent=True) or {}
    uid=str(body.get("user_id","")).strip()
    if not uid.isdigit() or len(uid)>20: return jsonify({"error":"Укажите числовой Telegram ID"}),400
    c=connect()
    try:
        cur=c.execute("INSERT OR IGNORE INTO admins(user_id,role,added_by,created_at) VALUES(?,?,?,?)",
                      (uid,"admin",str(g.user["id"]),int(time.time())))
        if cur.rowcount == 0: return jsonify({"error":"Этот ID уже администратор"}),409
        c.commit()
    finally: c.close()
    _admin_audit("admin.add",uid,{"added_by":str(g.user["id"])})
    return jsonify({"ok":True,"user_id":uid})

@app.delete("/api/admin/admins/<user_id>")
def admin_remove_admin(user_id):
    if not _admin_allowed(): return _admin_denied()
    if str(user_id)==OWNER_ADMIN_ID: return jsonify({"error":"Нельзя удалить главного администратора"}),403
    c=connect()
    cur=c.execute("DELETE FROM admins WHERE user_id=? AND role='admin'",(str(user_id),))
    c.commit(); count=cur.rowcount; c.close()
    if not count: return jsonify({"error":"Администратор не найден"}),404
    _admin_audit("admin.remove",str(user_id),{"removed_by":str(g.user["id"])})
    return jsonify({"ok":True,"user_id":str(user_id)})

# ---- Secure ETN administration API -------------------------------------------------
# Every /api/admin endpoint requires verified Telegram initData AND a Telegram ID in
# the server-side ADMIN_IDS environment variable. Frontend PIN/username checks are not
# authorization and are intentionally not used here.
ADMIN_STATE_KEYS = {
    "etn_match_submissions_v1",
    "etn_approved_match_stats_v1",
    "etn_organizer_applications_v1",
    "etn_screenshot_registrations_v1",
    "etn_support_tickets_v1",
    "etn_workflow_organizers_v1",
    "etn_workflow_tournaments_v1",
    "etn_workflow_tournament_regs_v1",
    "etn_player_bans_v1",
    "etn_bot_control_settings_v1",
    "etn_platform_settings_v1",
}
ADMIN_DEFAULTS = {
    "etn_match_submissions_v1": [],
    "etn_approved_match_stats_v1": [],
    "etn_organizer_applications_v1": [],
    "etn_screenshot_registrations_v1": [],
    "etn_support_tickets_v1": [],
    "etn_workflow_organizers_v1": [],
    "etn_workflow_tournaments_v1": [],
    "etn_workflow_tournament_regs_v1": [],
    "etn_player_bans_v1": [],
    "etn_bot_control_settings_v1": {
        "enabled": True, "maintenance": False, "registrations": True,
        "tournamentApplications": True, "organizerApplications": True,
        "supportEnabled": True, "name": "ETN × RAPIRA",
        "welcome": "Добро пожаловать в ETN × RAPIRA!", "announcement": "",
        "maintenanceMessage": "Платформа временно на техническом обслуживании. Попробуй позже."
    },
    "etn_platform_settings_v1": {"announcement": "", "maintenance": False, "registrations": True},
}

def _admin_allowed():
    return bool(getattr(g, "user", None)) and is_admin_user(str(g.user.get("id", "")))

def _admin_denied():
    return jsonify({"error": "Доступ запрещён. Ваш Telegram ID не добавлен в список администраторов."}), 403

def _admin_audit(action, target="", details=None):
    c = connect()
    with c:
        c.execute(
            "INSERT INTO admin_audit_log(admin_id,action,target,details,created_at) VALUES(?,?,?,?,?)",
            (str(g.user["id"]), str(action)[:100], str(target)[:200],
             json.dumps(details or {}, ensure_ascii=False, separators=(",", ":"))[:4000], int(time.time()))
        )
    c.close()

def _admin_read_state(c, key):
    row = c.execute("SELECT value,updated_at,updated_by FROM shared_state WHERE key=?", (key,)).fetchone()
    if not row:
        return {"found": False, "value": ADMIN_DEFAULTS.get(key), "updated_at": None, "updated_by": None}
    try: value = json.loads(row["value"])
    except Exception: value = ADMIN_DEFAULTS.get(key)
    return {"found": True, "value": value, "updated_at": row["updated_at"], "updated_by": row["updated_by"]}

def _admin_write_state(key, value, action="state.update"):
    if key not in ADMIN_STATE_KEYS:
        return False
    encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > 2_000_000:
        raise ValueError("Данные слишком большие: лимит 2 МБ")
    c = connect()
    with c:
        c.execute("INSERT INTO shared_state(key,value,updated_at,updated_by) VALUES(?,?,?,?) "
                  "ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at,updated_by=excluded.updated_by",
                  (key, encoded, int(time.time()), str(g.user["id"])))
    c.close()
    _admin_audit(action, key, {"bytes": len(encoded.encode("utf-8"))})
    return True

@app.get("/api/admin/overview")
def admin_overview():
    if not _admin_allowed(): return _admin_denied()
    c = connect()
    users = c.execute("SELECT COUNT(*) n FROM users").fetchone()["n"]
    teams = c.execute("SELECT COUNT(*) n FROM teams").fetchone()["n"]
    now = int(time.time())
    active = c.execute("SELECT COUNT(*) n FROM users WHERE last_seen>=?", (now - 30*86400,)).fetchone()["n"]
    states = {key: _admin_read_state(c, key) for key in ADMIN_STATE_KEYS}
    c.close()
    vals = {k: (v["value"] if isinstance(v.get("value"), list) else []) for k,v in states.items()}
    settings = states["etn_bot_control_settings_v1"].get("value") or ADMIN_DEFAULTS["etn_bot_control_settings_v1"]
    return jsonify({"ok": True, "server_time": now, "registered_users": users, "active_users_30d": active,
      "teams": teams, "matches_total": len(vals["etn_match_submissions_v1"]),
      "matches_pending": sum(1 for x in vals["etn_match_submissions_v1"] if isinstance(x,dict) and str(x.get("status","" )).lower() in {"на проверке","на рассмотрении","pending"}),
      "organizer_pending": sum(1 for x in vals["etn_organizer_applications_v1"] if isinstance(x,dict) and str(x.get("status","" )).lower() in {"на рассмотрении","на проверке","pending"}),
      "support_open": sum(1 for x in vals["etn_support_tickets_v1"] if isinstance(x,dict) and str(x.get("status","Новое")).lower() not in {"решено","закрыто","resolved"}),
      "tournaments": len(vals["etn_workflow_tournaments_v1"]), "settings": settings,
      "storage": {k: {"found":v["found"],"updated_at":v["updated_at"]} for k,v in states.items()}})

@app.get("/api/admin/users")
def admin_users():
    if not _admin_allowed(): return _admin_denied()
    q = str(request.args.get("q", "")).strip().lower()[:100]
    try: limit = max(1, min(500, int(request.args.get("limit", "200"))))
    except ValueError: limit = 200
    c = connect()
    rows = c.execute("SELECT user_id,username,first_name,last_seen FROM users ORDER BY last_seen DESC LIMIT 1000").fetchall()
    result=[]
    for r in rows:
        item={"id":str(r["user_id"]),"username":r["username"] or "","first_name":r["first_name"] or "","last_seen":r["last_seen"]}
        if q and q not in (item["id"]+" "+item["username"]+" "+item["first_name"]).lower(): continue
        prof=c.execute("SELECT value FROM user_state WHERE user_id=? AND key='etn_player_profile_v1'",(item["id"],)).fetchone()
        if prof:
            try:
                p=json.loads(prof["value"]); item["profile"]={"nick":p.get("nick", ""),"team":p.get("team", ""),"rank":p.get("rank",p.get("level",""))}
            except Exception: item["profile"]={}
        result.append(item)
        if len(result)>=limit: break
    c.close()
    return jsonify({"ok":True,"users":result,"total_returned":len(result)})

@app.get("/api/admin/state")
def admin_all_state():
    if not _admin_allowed(): return _admin_denied()
    c=connect(); result={key:_admin_read_state(c,key) for key in sorted(ADMIN_STATE_KEYS)}; c.close()
    return jsonify({"ok":True,"states":result})

@app.put("/api/admin/state/<path:key>")
def admin_update_state(key):
    if not _admin_allowed(): return _admin_denied()
    if key not in ADMIN_STATE_KEYS: return jsonify({"error":"Ключ не разрешён для администрирования"}),404
    body=request.get_json(silent=True) or {}
    if "value" not in body: return jsonify({"error":"Поле value обязательно"}),400
    if key.endswith("_v1") and key not in {"etn_bot_control_settings_v1","etn_platform_settings_v1"} and not isinstance(body["value"],list):
        return jsonify({"error":"Для этого раздела ожидается список записей"}),400
    try: _admin_write_state(key,body["value"])
    except ValueError as e: return jsonify({"error":str(e)}),413
    return jsonify({"ok":True,"key":key,"updated_at":int(time.time())})

@app.get("/api/admin/teams")
def admin_list_teams():
    if not _admin_allowed(): return _admin_denied()
    c=connect(); rows=c.execute("SELECT id,name,tag,region,captain_id,captain_username,members_json,created_at FROM teams ORDER BY created_at DESC").fetchall(); c.close()
    teams=[]
    for r in rows:
        try: members=json.loads(r["members_json"])
        except Exception: members=[]
        teams.append({"id":r["id"],"name":r["name"],"tag":r["tag"],"region":r["region"],"captain_id":r["captain_id"],"captain":r["captain_username"],"members":members,"created_at":r["created_at"]})
    return jsonify({"ok":True,"teams":teams})

@app.post("/api/admin/teams")
def admin_create_team():
    if not _admin_allowed(): return _admin_denied()
    body=request.get_json(silent=True) or {}
    name=str(body.get("name","")).strip(); tag=str(body.get("tag","")).strip().upper(); region=str(body.get("region","Другой")).strip()
    captain=str(body.get("captain","")).strip().lstrip("@").lower()
    extras=body.get("members",[])
    valid_regions={"СНГ","Европа","Северная Америка","Южная Америка","Азия","Океания","Другой"}
    if not name or len(name)>32: return jsonify({"error":"Название команды должно содержать от 1 до 32 символов"}),400
    if len(tag)>8 or any(not(ch.isalnum() or ch in "_-") for ch in tag): return jsonify({"error":"Некорректный тег команды"}),400
    if region not in valid_regions: return jsonify({"error":"Неизвестный регион"}),400
    if not captain or not isinstance(extras,list) or len(extras)>9: return jsonify({"error":"Укажи капитана и до 9 участников"}),400
    usernames=[captain]
    for value in extras:
        u=str(value or "").strip().lstrip("@").lower()
        if len(u)<5 or not all(ch.isalnum() or ch=="_" for ch in u): return jsonify({"error":"Некорректный Telegram username участника"}),400
        usernames.append(u)
    if len(set(usernames))!=len(usernames): return jsonify({"error":"Участник указан несколько раз"}),400
    c=connect(); placeholders=','.join('?' for _ in usernames)
    rows=c.execute(f"SELECT user_id,username FROM users WHERE lower(username) IN ({placeholders})",usernames).fetchall()
    by={str(r["username"] or "").lower():str(r["user_id"]) for r in rows if r["username"]}
    missing=["@"+u for u in usernames if u not in by]
    if missing: c.close(); return jsonify({"error":"Не зарегистрированы в ETN: "+", ".join(missing)}),400
    ids=set(by.values())
    for row in c.execute("SELECT name,members_json FROM teams").fetchall():
        try: current=json.loads(row["members_json"])
        except Exception: current=[]
        if any(str(m.get("user_id","")) in ids for m in current if isinstance(m,dict)):
            c.close(); return jsonify({"error":"Один из игроков уже состоит в другой команде"}),409
    team_id="team_"+str(int(time.time()*1000)); members=[{"user_id":by[u],"username":u,"role":"Капитан" if i==0 else "Участник"} for i,u in enumerate(usernames)]
    try:
        with c: c.execute("INSERT INTO teams(id,name,tag,region,captain_id,captain_username,members_json,created_at) VALUES(?,?,?,?,?,?,?,?)",(team_id,name,tag,region,by[captain],captain,json.dumps(members,ensure_ascii=False),int(time.time())))
    except sqlite3.IntegrityError:
        c.close(); return jsonify({"error":"Команда с таким названием уже существует"}),409
    c.close(); _admin_audit("team.create",team_id,{"name":name,"members":len(members)})
    return jsonify({"ok":True,"team":{"id":team_id,"name":name,"tag":tag,"region":region,"captain":captain,"members":members}}),201

@app.delete("/api/admin/teams/<path:team_id>")
def admin_delete_team(team_id):
    if not _admin_allowed(): return _admin_denied()
    c=connect(); row=c.execute("SELECT name FROM teams WHERE id=?",(team_id,)).fetchone()
    if not row: c.close(); return jsonify({"error":"Команда не найдена"}),404
    with c: c.execute("DELETE FROM teams WHERE id=?",(team_id,))
    c.close(); _admin_audit("team.delete",team_id,{"name":row["name"]})
    return jsonify({"ok":True})

@app.post("/api/admin/users/<path:user_id>/ban")
def admin_ban_user(user_id):
    if not _admin_allowed(): return _admin_denied()
    body=request.get_json(silent=True) or {}; reason=str(body.get("reason",""))[:300]
    try: until=int(body.get("until",0))
    except (TypeError,ValueError): until=0
    if until<=int(time.time()): return jsonify({"error":"Дата окончания BAN должна быть в будущем"}),400
    c=connect(); user=c.execute("SELECT username,first_name FROM users WHERE user_id=?",(str(user_id),)).fetchone(); c.close()
    if not user: return jsonify({"error":"Пользователь не найден"}),404
    bans=_admin_read_key("etn_player_bans_v1")
    bans=[b for b in bans if not (isinstance(b,dict) and str(b.get("user_id",""))==str(user_id))]
    bans.insert(0,{"id":"ban_"+str(int(time.time()*1000)),"user_id":str(user_id),"nick":user["username"] or user["first_name"] or str(user_id),"until":time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime(until)),"reason":reason,"createdAt":time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),"createdBy":str(g.user["id"])})
    _admin_write_state("etn_player_bans_v1",bans,"user.ban")
    return jsonify({"ok":True,"ban":bans[0]})

def _admin_read_key(key):
    c=connect(); r=_admin_read_state(c,key); c.close(); v=r.get("value"); return v if isinstance(v,list) else []

@app.delete("/api/admin/bans/<path:ban_id>")
def admin_remove_ban(ban_id):
    if not _admin_allowed(): return _admin_denied()
    bans=_admin_read_key("etn_player_bans_v1"); new=[b for b in bans if not (isinstance(b,dict) and str(b.get("id"))==str(ban_id))]
    if len(new)==len(bans): return jsonify({"error":"BAN не найден"}),404
    _admin_write_state("etn_player_bans_v1",new,"user.unban")
    return jsonify({"ok":True})

@app.get("/api/admin/audit")
def admin_audit_list():
    if not _admin_allowed(): return _admin_denied()
    c=connect(); rows=c.execute("SELECT id,admin_id,action,target,details,created_at FROM admin_audit_log ORDER BY id DESC LIMIT 100").fetchall(); c.close()
    out=[]
    for r in rows:
        try: details=json.loads(r["details"])
        except Exception: details={}
        out.append({"id":r["id"],"admin_id":r["admin_id"],"action":r["action"],"target":r["target"],"details":details,"created_at":r["created_at"]})
    return jsonify({"ok":True,"events":out})

@app.post("/api/support-tickets")
def create_support_ticket():
    body=request.get_json(silent=True) or {}
    settings=_admin_read_key("etn_bot_control_settings_v1")
    if settings and settings.get("supportEnabled") is False:
        return jsonify({"error":"Обращения в поддержку временно отключены"}),503
    topic=str(body.get("topic","Другое"))[:80].strip() or "Другое"
    message=str(body.get("message","")).strip(); contact=str(body.get("contact","")).strip()[:100]
    if len(message)<15 or len(message)>2000: return jsonify({"error":"Сообщение должно содержать от 15 до 2000 символов"}),400
    tickets=_admin_read_key("etn_support_tickets_v1")
    ticket={"id":"sup_"+str(int(time.time()*1000)),"topic":topic,"message":message,"contact":contact or ("@"+g.user["username"] if g.user.get("username") else str(g.user["id"])),"date":time.strftime('%Y-%m-%d %H:%M UTC',time.gmtime()),"status":"Новое","user_id":str(g.user["id"]),"username":g.user.get("username","")}
    tickets.insert(0,ticket)
    try: _admin_write_state("etn_support_tickets_v1",tickets,"support.create")
    except ValueError as e: return jsonify({"error":str(e)}),413
    return jsonify({"ok":True,"ticket":ticket}),201


@app.errorhandler(Exception)
def handle_error(e):
    if isinstance(e, HTTPException):
        return jsonify({"error": e.description}), e.code
    app.logger.exception("Unhandled API error")
    return jsonify({"error": "Internal server error"}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")))
