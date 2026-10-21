import logging
import os
import sqlite3
import time

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, WebAppInfo
from telegram.ext import Application, CommandHandler

logging.basicConfig(
    format="%(asctime)s | %(levelname)s | %(name)s: %(message)s",
    level=logging.INFO,
)

TOKEN = os.getenv("BOT_TOKEN", "").strip()
WEBAPP_URL = os.getenv(
    "WEBAPP_URL", "https://etnrapiraonlineorig.netlify.app/"
).strip()


def register_bot_user(user):
    if not user:
        return
    db_path = os.environ.get("ETN_DB_PATH", "/data/etn.sqlite3")
    os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
    with sqlite3.connect(db_path, timeout=15) as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS users (user_id TEXT PRIMARY KEY, username TEXT, first_name TEXT, last_seen INTEGER NOT NULL)")
        conn.execute(
            "INSERT INTO users(user_id,username,first_name,last_seen) VALUES(?,?,?,?) "
            "ON CONFLICT(user_id) DO UPDATE SET username=excluded.username, first_name=excluded.first_name, last_seen=excluded.last_seen",
            (str(user.id), user.username or "", user.first_name or "", int(time.time())),
        )


def read_platform_settings():
    """Read platform control flags from the same persistent SQLite DB as the API."""
    db_path = os.environ.get("ETN_DB_PATH", "/data/etn.sqlite3")
    try:
        with sqlite3.connect(db_path, timeout=5) as conn:
            row = conn.execute("SELECT value FROM shared_state WHERE key=?", ("etn_bot_control_settings_v1",)).fetchone()
        import json
        if row:
            value = json.loads(row[0])
            if isinstance(value, dict):
                return value
    except Exception:
        logging.debug("Platform settings not configured yet", exc_info=True)
    return {"enabled": True, "maintenance": False, "supportEnabled": True,
            "welcome": "Добро пожаловать в ETN × RAPIRA!",
            "maintenanceMessage": "Платформа временно на техническом обслуживании. Попробуй позже."}


async def start(update, context):
    message = update.effective_message
    if not message:
        return
    settings = read_platform_settings()
    if settings.get("enabled") is False:
        await message.reply_text("ETN временно недоступен. Попробуй позже.")
        return
    if settings.get("maintenance") is True:
        await message.reply_text(str(settings.get("maintenanceMessage") or "Платформа на техническом обслуживании.")[:500])
        return
    try:
        register_bot_user(update.effective_user)
    except Exception:
        logging.exception("Could not persist Telegram bot user")

    if not WEBAPP_URL.startswith("https://"):
        await message.reply_text("Сайт пока недоступен. Попробуй чуть позже.")
        logging.error("WEBAPP_URL is missing or is not HTTPS")
        return

    keyboard = [[
        InlineKeyboardButton(
            "Открыть ETN × RAPIRA",
            web_app=WebAppInfo(url=WEBAPP_URL),
        )
    ]]
    welcome = str(settings.get("welcome") or "Привет! Жми кнопку ниже, чтобы открыть ETN × RAPIRA.")[:1000]
    if settings.get("announcement"):
        welcome += "\n\n📣 " + str(settings.get("announcement"))[:1000]
    await message.reply_text(welcome, reply_markup=InlineKeyboardMarkup(keyboard))


def main():
    if not TOKEN:
        raise RuntimeError("Не задана переменная BOT_TOKEN")
    if not WEBAPP_URL.startswith("https://"):
        raise RuntimeError("WEBAPP_URL должен быть HTTPS-адресом")

    app = Application.builder().token(TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    logging.info("Bot started; polling for Telegram updates")
    app.run_polling(drop_pending_updates=False)


if __name__ == "__main__":
    main()
