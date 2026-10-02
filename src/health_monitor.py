import sqlite3
from .config import DB_PATH, SOURCES, BLACKLIST


def _columns(con, table):
    return {row[1] for row in con.execute(f"PRAGMA table_info({table})").fetchall()}


def init_db():
    """
    ساخت/ارتقای دیتابیس منابع.

    نکته مهم: نسخه‌های قدیمی Xfinder جدول sources را با ستون‌های
    متفاوتی ساخته بودند (مثلاً failures و score). این تابع بدون حذف
    اطلاعات قبلی، ستون‌های جدید را اضافه و مقادیر قدیمی را منتقل می‌کند.
    """
    con = sqlite3.connect(DB_PATH)
    try:
        con.execute("""CREATE TABLE IF NOT EXISTS sources(
          name TEXT PRIMARY KEY,
          url TEXT,
          trust REAL DEFAULT 0,
          last_ok TEXT,
          consecutive_failures INTEGER DEFAULT 0,
          config_count INTEGER DEFAULT 0,
          success_rate REAL DEFAULT 0,
          avg_ping REAL DEFAULT 0,
          disabled INTEGER DEFAULT 0
        )""")

        cols = _columns(con, "sources")

        # مهاجرت دیتابیس‌های قدیمی بدون DROP TABLE.
        additions = {
            "url": "TEXT",
            "trust": "REAL DEFAULT 0",
            "consecutive_failures": "INTEGER DEFAULT 0",
            "config_count": "INTEGER DEFAULT 0",
            "success_rate": "REAL DEFAULT 0",
            "avg_ping": "REAL DEFAULT 0",
            "disabled": "INTEGER DEFAULT 0",
            "last_ok": "TEXT",
        }
        for name, definition in additions.items():
            if name not in cols:
                con.execute(f"ALTER TABLE sources ADD COLUMN {name} {definition}")

        cols = _columns(con, "sources")

        # نگاشت نام ستون‌های قدیمی به ساختار جدید.
        if "score" in cols:
            con.execute("UPDATE sources SET trust = COALESCE(NULLIF(trust, 0), score)")
        if "failures" in cols:
            con.execute(
                "UPDATE sources SET consecutive_failures = "
                "COALESCE(NULLIF(consecutive_failures, 0), failures)"
            )

        # منابع فعال پروژه را ثبت/به‌روزرسانی می‌کنیم.
        for source in SOURCES:
            if source["name"] in BLACKLIST:
                continue
            con.execute(
                """INSERT INTO sources(name, url, trust) VALUES(?, ?, ?)
                   ON CONFLICT(name) DO UPDATE SET
                     url=excluded.url,
                     trust=excluded.trust""",
                (source["name"], source["url"], source.get("trust", 0)),
            )

        con.commit()
    finally:
        con.close()


def active_sources():
    init_db()
    con = sqlite3.connect(DB_PATH)
    try:
        rows = con.execute(
            "SELECT name,url,trust,disabled FROM sources WHERE disabled=0"
        ).fetchall()
    finally:
        con.close()
    return [
        {"name": r[0], "url": r[1], "trust": r[2], "disabled": r[3]}
        for r in rows
    ]


if __name__ == "__main__":
    init_db()
    print("health database ready")
