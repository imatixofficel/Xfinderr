import re
import os
import datetime
from pathlib import Path

README = Path("README.md")

now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
run_number = os.environ.get("GITHUB_RUN_NUMBER", "0")

total_configs = 0
all_txt = Path("output/all.txt")
if all_txt.exists():
    try:
        with all_txt.open("r", encoding="utf-8", errors="ignore") as f:
            total_configs = sum(1 for line in f if line.strip())
    except Exception:
        total_configs = 0

text = README.read_text(encoding="utf-8")

block = f"""<!-- HEARTBEAT:START -->
آخرین اجرا: {now}
شماره اجرا: {run_number}
تعداد کانفیگ‌ها: {total_configs}
وضعیت: ✅ فعال
<!-- HEARTBEAT:END -->"""

new_text = re.sub(
    r"<!-- HEARTBEAT:START -->.*?<!-- HEARTBEAT:END -->",
    block,
    text,
    flags=re.DOTALL,
)

if new_text != text:
    README.write_text(new_text, encoding="utf-8")
    print("README updated")
else:
    print("README unchanged")
