import asyncio
import logging
import sqlite3
import os
from datetime import datetime
from functools import partial
import httpx
from aiogram import Bot, Dispatcher, types
from aiogram.filters import Command
from aiogram.client.session.aiohttp import AiohttpSession
from aiogram.exceptions import TelegramForbiddenError
from dotenv import load_dotenv

load_dotenv()
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
PROXY_URL = os.getenv("PROXY_URL")
CHECK_INTERVAL = 60
REQUEST_DELAY = 0
DB_PATH = "incidents.db"
SUBSCRIBERS_DB_PATH = "subscribers.db"

logging.basicConfig(level=logging.WARNING, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("aiohttp").setLevel(logging.WARNING)
logging.getLogger("aiohttp.access").setLevel(logging.WARNING)
logging.getLogger("aiohttp.client").setLevel(logging.WARNING)

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS incidents (id INTEGER PRIMARY KEY AUTOINCREMENT, start_time TIMESTAMP NOT NULL, end_time TIMESTAMP, urls TEXT NOT NULL)")
    cursor.execute("CREATE TABLE IF NOT EXISTS incidents_anti (id INTEGER PRIMARY KEY AUTOINCREMENT, start_time TIMESTAMP NOT NULL, end_time TIMESTAMP, urls TEXT NOT NULL)")
    cursor.execute("CREATE TABLE IF NOT EXISTS incidents_grey (id INTEGER PRIMARY KEY AUTOINCREMENT, start_time TIMESTAMP NOT NULL, end_time TIMESTAMP, urls TEXT NOT NULL)")
    cursor.execute("CREATE TABLE IF NOT EXISTS incidents_anti_grey (id INTEGER PRIMARY KEY AUTOINCREMENT, start_time TIMESTAMP NOT NULL, end_time TIMESTAMP, urls TEXT NOT NULL)")
    cursor.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value INTEGER)")
    cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('max_banner_index', 19)")
    cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('max_anti_index', 2)")
    conn.commit()
    conn.close()

    conn = sqlite3.connect(SUBSCRIBERS_DB_PATH)
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS subscribers (user_id INTEGER PRIMARY KEY, subscribed INTEGER DEFAULT 1)")
    conn.commit()
    conn.close()

def get_setting(key, default=1):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT value FROM settings WHERE key = ?", (key,))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else default

def update_setting(key, value):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("UPDATE settings SET value = ? WHERE key = ?", (value, key))
    conn.commit()
    conn.close()

def get_active_incident(table="incidents"):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM {table} WHERE end_time IS NULL ORDER BY start_time DESC LIMIT 1")
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def create_incident(urls, start_time, table="incidents"):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(f"INSERT INTO {table} (start_time, end_time, urls) VALUES (?, ?, ?)",
                   (start_time.isoformat(), None, ",".join(urls)))
    idx = cursor.lastrowid
    conn.commit()
    conn.close()
    return idx

def close_incident(incident_id, end_time, table="incidents"):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(f"SELECT start_time FROM {table} WHERE id = ?", (incident_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return None, 0

    start_time = datetime.fromisoformat(row["start_time"])
    cursor.execute(f"UPDATE {table} SET end_time = ? WHERE id = ?", (end_time.isoformat(), incident_id))
    conn.commit()
    conn.close()
    return start_time, int((end_time - start_time).total_seconds() / 60)

def get_subscribers():
    conn = sqlite3.connect(SUBSCRIBERS_DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT user_id FROM subscribers WHERE subscribed = 1")
    rows = cursor.fetchall()
    conn.close()
    return [row[0] for row in rows]

def subscribe_user(user_id):
    conn = sqlite3.connect(SUBSCRIBERS_DB_PATH)
    cursor = conn.cursor()
    cursor.execute("INSERT OR REPLACE INTO subscribers (user_id, subscribed) VALUES (?, 1)", (user_id,))
    conn.commit()
    conn.close()

def unsubscribe_user(user_id):
    conn = sqlite3.connect(SUBSCRIBERS_DB_PATH)
    cursor = conn.cursor()
    cursor.execute("UPDATE subscribers SET subscribed = 0 WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()

async def check_url(client, url):
    result = {"url": url, "status": "чисто", "is_scam": False, "exists": False, "error": None}
    try:
        response = await client.get(url, timeout=10.0)
        if response.status_code == 200:
            result["exists"] = True
            lines = response.text.strip().split("\n")
            if len(lines) >= 4 or (lines and lines[0].strip() == "0"):
                result["status"] = "АВАРИЙКА"
                result["is_scam"] = True
        elif response.status_code == 404 or response.status_code == 403:
            result["exists"] = False
        else:
            result["error"] = f"HTTP {response.status_code}"
    except Exception as e:
        result["error"] = str(e)
        logger.error(f"Ошибка при проверке {url}: {e}")
    return result

async def check_grey_url(client, url):
    result = {"url": url, "status": "чисто", "is_scam": False, "exists": False, "error": None, "version": None}
    try:
        response = await client.get(url, timeout=10.0)
        if response.status_code == 200:
            result["exists"] = True
            text = response.text.strip()
            lines = [line.strip() for line in text.split("\n") if line.strip()]

            if len(lines) >= 2 and any(l.startswith("Version=") for l in lines):
                result["status"] = "СЕРЫЙ БАННЕР"
                result["is_scam"] = True
                for l in lines:
                    if l.startswith("Version="):
                        result["version"] = l.split("=", 1)[1]
                        break
        elif response.status_code == 404 or response.status_code == 403:
            result["exists"] = False
        else:
            result["error"] = f"HTTP {response.status_code}"
    except Exception as e:
        result["error"] = str(e)
        logger.error(f"Ошибка при проверке серого баннера {url}: {e}")
    return result

class IncidentMonitor:
    def __init__(self, bot):
        self.bot = bot
        self.active_id = None
        self.active_anti_id = None
        self.active_grey_id = None
        self.active_anti_grey_id = None
        self.last_results = []
        self.clean_counter = {"incidents": 0, "incidents_anti": 0, "incidents_grey": 0, "incidents_anti_grey": 0}
        self.CONFIRM_THRESHOLD = 3

    async def restore_from_db(self):
        for attr, table in [("active_id", "incidents"), ("active_anti_id", "incidents_anti"),
                            ("active_grey_id", "incidents_grey"), ("active_anti_grey_id", "incidents_anti_grey")]:
            inc = get_active_incident(table)
            if inc: setattr(self, attr, inc["id"])

    async def check_group(self, client, base_name, setting_key, is_anti=False):
        max_idx = get_setting(setting_key)
        if not is_anti:
            urls = ["https://a.tiktokmod.pro/banner.conf"] + [f"https://a.tiktokmod.pro/banner{i}.conf" for i in range(2, max_idx + 1)]
        else:
            urls = ["https://a.tiktokmod.pro/banner_anti.conf"] + [f"https://a.tiktokmod.pro/banner_anti{i}.conf" for i in range(2, max_idx + 1)]

        results = []
        for url in urls:
            res = await check_url(client, url)
            results.append(res)
            await asyncio.sleep(REQUEST_DELAY)

        probe_idx = max_idx + 1
        while True:
            suffix = f"_anti{probe_idx}" if is_anti else f"{probe_idx}"
            probe_url = f"https://a.tiktokmod.pro/banner{suffix}.conf"
            res = await check_url(client, probe_url)
            if res["exists"]:
                results.append(res)
                update_setting(setting_key, probe_idx)
                await self.notify_new_config(probe_url)
                probe_idx += 1
            else:
                break
        return results

    async def check_grey_group(self, client):
        urls = ["https://update.9mod.com/Tiktok_m.txt", "https://update.9mod.com/Tiktok_c.txt", "https://update.9mod.com/Tiktok_P.txt"]
        results = []
        for url in urls:
            res = await check_grey_url(client, url)
            results.append(res)
            await asyncio.sleep(REQUEST_DELAY)
        return results

    async def check_anti_grey_group(self, client):
        urls = ["https://update.9mod.com/TikTok_AntiCloud.txt"]
        results = []
        for url in urls:
            res = await check_grey_url(client, url)
            results.append(res)
            await asyncio.sleep(REQUEST_DELAY)
        return results

    async def check_and_notify(self):
        async with httpx.AsyncClient() as client:
            std_results = await self.check_group(client, "banner", "max_banner_index", False)
            anti_results = await self.check_group(client, "banner_anti", "max_anti_index", True)
            grey_results = await self.check_grey_group(client)
            anti_grey_results = await self.check_anti_grey_group(client)

        self.last_results = [r for r in (std_results + anti_results + grey_results + anti_grey_results) if r["exists"] or r["error"]]

        await self._handle_incident_logic(std_results, "active_id", "incidents", "ОБЫЧНАЯ")
        await self._handle_incident_logic(anti_results, "active_anti_id", "incidents_anti", "АНТИ")
        await self._handle_incident_logic(grey_results, "active_grey_id", "incidents_grey", "СЕРЫЙ ОБЫЧНЫЙ")
        await self._handle_incident_logic(anti_grey_results, "active_anti_grey_id", "incidents_anti_grey", "СЕРЫЙ АНТИ")

    async def _handle_incident_logic(self, results, attr_name, table, label):
        scam_results = [r for r in results if r["is_scam"]]
        scam_urls = [r["url"] for r in scam_results]
        current_id = getattr(self, attr_name)

        if scam_urls:
            self.clean_counter[table] = 0
            if current_id is None:
                new_id = create_incident(scam_urls, datetime.now(), table)
                setattr(self, attr_name, new_id)
                await self.notify_scam_start(scam_results, datetime.now(), label)
        elif current_id is not None:
            self.clean_counter[table] += 1
            if self.clean_counter[table] >= self.CONFIRM_THRESHOLD:
                st, dur = close_incident(current_id, datetime.now(), table)
                await self.notify_scam_end(st, dur, label)
                setattr(self, attr_name, None)
                self.clean_counter[table] = 0

    async def notify_new_config(self, url):
        msg = f"✨ Новый конфиг!\n\n<code>{url}</code>"
        await self._broadcast(msg)

    async def notify_scam_start(self, scam_results, st, label):
        msg = f"🚨 {label}: АВАРИЙКА\n\nНачало: {st.strftime('%H:%M:%S')}\n"
        for r in scam_results:
            url_name = r['url'].split('/')[-1]
            version_info = f" ({r.get('version')})" if r.get('version') else ""
            msg += f"• <code>{url_name}</code>{version_info}\n"
        await self._broadcast(msg)

    async def notify_scam_end(self, st, dur, label):
        msg = f"✅ {label}: Чисто\n\nДлительность: {dur} мин\nНачало: {st.strftime('%H:%M:%S')}"
        await self._broadcast(msg)

    async def _broadcast(self, msg):
        for uid in get_subscribers():
            try: await self.bot.send_message(uid, msg, parse_mode="HTML")
            except TelegramForbiddenError: unsubscribe_user(uid)
            except Exception as e: logger.warning(f"Error sending {uid}: {e}")

    async def get_status_message(self):
        if not self.last_results: return "Данные собираются"
        msg = f"Статус (Проверено: {len(self.last_results)})\n\n"
        for r in self.last_results:
            icon = "🔴" if r["is_scam"] else "❌" if r["error"] else "🟢"
            url_name = r['url']
            version_info = f" ({r.get('version')})" if r.get('version') else ""
            msg += f"{icon} <code>{url_name}</code>{version_info}\n"
        return msg

async def cmd_start(m: types.Message):
    await m.answer("Бот мониторинга авариек\n\n/status - состояние\n/history - история\n/yes - подписка\n/no - отписка")

async def cmd_status(m: types.Message, monitor: IncidentMonitor):
    await m.answer(await monitor.get_status_message(), parse_mode="HTML")

async def cmd_history(m: types.Message):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("""
        SELECT 'STD' as type, start_time, end_time FROM incidents WHERE end_time IS NOT NULL AND end_time != ''
        UNION ALL SELECT 'ANTI' as type, start_time, end_time FROM incidents_anti WHERE end_time IS NOT NULL AND end_time != ''
        UNION ALL SELECT 'GREY' as type, start_time, end_time FROM incidents_grey WHERE end_time IS NOT NULL AND end_time != ''
        UNION ALL SELECT 'ANTI-GREY' as type, start_time, end_time FROM incidents_anti_grey WHERE end_time IS NOT NULL AND end_time != ''
        ORDER BY start_time DESC LIMIT 50
    """)
    rows = cursor.fetchall()
    conn.close()
    if not rows: return await m.answer("История пуста")
    txt = "Последние 50:\n\n"
    for r in rows:
        if not r['start_time'] or not r['end_time']:
            continue 
        try:
            start_dt = datetime.fromisoformat(r['start_time'])
            end_dt = datetime.fromisoformat(r['end_time'])
            st_str = start_dt.strftime('%d.%m %H:%M')
            dur = int((end_dt - start_dt).total_seconds() / 60)
            txt += f"[{r['type']}] {st_str} — {dur} мин\n"
        except ValueError:
            continue
    await m.answer(txt, parse_mode="HTML")

async def periodic_check(monitor):
    while True:
        try: await monitor.check_and_notify()
        except Exception as e: logger.error(f"Check error: {e}")
        await asyncio.sleep(CHECK_INTERVAL)

async def main():
    init_db()
    session = AiohttpSession(proxy=PROXY_URL) if PROXY_URL else None
    bot = Bot(token=TELEGRAM_BOT_TOKEN, session=session)
    dp = Dispatcher()

    monitor = IncidentMonitor(bot)
    await monitor.restore_from_db()

    dp.message.register(cmd_start, Command("start"))
    dp.message.register(partial(cmd_status, monitor=monitor), Command("status"))
    dp.message.register(cmd_history, Command("history"))
    dp.message.register(lambda m: subscribe_user(m.from_user.id) or m.answer("✅"), Command("yes"))
    dp.message.register(lambda m: unsubscribe_user(m.from_user.id) or m.answer("❌"), Command("no"))

    asyncio.create_task(periodic_check(monitor))
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())
