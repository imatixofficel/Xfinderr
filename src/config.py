from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
OUTPUT_DIR = ROOT / "output"
DB_PATH = ROOT / "sources.db"

CONCURRENCY = 180
TCP_TIMEOUT = 4.0
HTTP_TIMEOUT = 5.0
IP_SCAN_CONCURRENCY = 160
IP_SCAN_TIMEOUT = 2.5
MAX_IPS_TO_SCAN = 400
MIN_TRUST = 60
MAX_REMIX_PING = 70
REMIX_PER_CONFIG = 3

SOURCES = [
    {"name":"Au1rxx/free-vpn-subscriptions","url":"https://github.com/Au1rxx/free-vpn-subscriptions/raw/main/output/v2ray-base64.txt","trust":100,"has_http_test":True},
    {"name":"barry-far/V2ray-Config","url":"https://raw.githubusercontent.com/barry-far/V2ray-Config/main/All_Configs_Sub.txt","trust":92,"has_http_test":False},
    {"name":"soroushmirzaei/telegram-configs-collector","url":"https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/splitted/mixed","trust":90,"has_http_test":False},
    {"name":"Delta-Kronecker/V2ray-Config","url":"https://github.com/Delta-Kronecker/V2ray-Config/raw/refs/heads/main/config/farg/all_configs.json","trust":90,"has_http_test":False},
    {"name":"mahdibland/V2RayAggregator","url":"https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge_base64.txt","trust":88,"has_http_test":False},
    {"name":"Epodonios/v2ray-configs","url":"https://github.com/Epodonios/v2ray-configs/raw/main/All_Configs_Sub.txt","trust":85,"has_http_test":False},
    {"name":"MatinGhanbari/v2ray-configs","url":"https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/super-sub.txt","trust":85,"has_http_test":False},
    {"name":"ebrasha/free-v2ray-public-list","url":"https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/main/V2Ray-Config-By-EbraSha.txt","trust":84,"has_http_test":False},
    {"name":"R3ZARAHIMI/tg-v2ray-configs-every2h","url":"https://raw.githubusercontent.com/R3ZARAHIMI/tg-v2ray-configs-every2h/main/all.txt","trust":80,"has_http_test":False},
]
CLEAN_IPS_URL = "https://raw.githubusercontent.com/imatixofficel/Scanner-matix/main/data/clean_ips.json"
BLACKLIST = {"v2ray_configs_pool","nim_vpn_ir","outline_vpn","hope_net","proxystore11","yaney_01","fnet00","ShadowProxy66","zibanabz"}

# --- سرعت و حجم خروجی ---
MAX_PUBLISH_BASE = 1200
MIN_PUBLISH_TEST_LEVEL = "tcp"      # فقط سریع‌ترین کانفیگ‌های اصلی منتشر می‌شوند تا سایت سنگین نشود
REMIX_BASE_LIMIT = 250       # فقط بهترین کانفیگ‌ها با IP تمیز ترکیب می‌شوند
# --- WireGuard (Cloudflare WARP) ---
WG_ACCOUNTS = 3              # تعداد حساب WARP که نگه‌داری می‌شود
WG_ENDPOINTS_PER_ACCOUNT = 6 # هر حساب با چند IP تمیز ساخته می‌شود
WG_PORT = 2408
WARP_ACCOUNTS_FILE = DATA_DIR / "warp_accounts.json"

X_RAY_BIN = "./bin/xray"
XRAY_CONCURRENCY = 12
XRAY_TIMEOUT = 8
XRAY_TEST_URL = "https://www.gstatic.com/generate_204"
