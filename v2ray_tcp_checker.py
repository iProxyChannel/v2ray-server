#!/usr/bin/env python3
"""
V2Ray Sub-Link TCP Checker
---------------------------
- چند تا ساب‌لینک (از GitHub Secrets) می‌گیره
- محتوای هر ساب‌لینک رو دانلود و base64-decode می‌کنه
- کانفیگ‌های vmess / vless / trojan / ss رو پارس می‌کنه
- برای هر کانفیگ یه تست TCP ساده می‌گیره (فقط اتصال socket، بدون هندشیک xray)
- کانفیگ‌های فعال رو با ریمارک جدید (نام + وضعیت) توی یه فایل txt می‌نویسه

نحوه‌ی اجرا:
    export SUB_LINKS="https://sub1.example.com/link1,https://sub2.example.com/link2"
    python3 v2ray_tcp_checker.py

یا با فایل ورودی:
    python3 v2ray_tcp_checker.py --links-file links.txt

خروجی:
    fast_servers.txt  (هر خط یک کانفیگ فعال با ریمارک جدید)
"""

import argparse
import base64
import binascii
import concurrent.futures
import json
import logging
import os
import socket
import sys
import time
import urllib.parse
import urllib.request

# ----------------------------- تنظیمات پیش‌فرض -----------------------------

TCP_TIMEOUT = float(os.environ.get("TCP_TIMEOUT", "3"))        # ثانیه، تایم‌اوت هر تست TCP
MAX_WORKERS = int(os.environ.get("MAX_WORKERS", "50"))          # تعداد ترد هم‌زمان برای تست
FETCH_TIMEOUT = float(os.environ.get("FETCH_TIMEOUT", "10"))    # ثانیه، تایم‌اوت دانلود ساب‌لینک
OUTPUT_FILE = os.environ.get("OUTPUT_FILE", "fast_servers.txt")
REMARK_PREFIX = os.environ.get("REMARK_PREFIX", "✅")           # پیشوند ریمارک برای کانفیگ فعال

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("v2ray-checker")


# ----------------------------- گرفتن لیست ساب‌لینک‌ها -----------------------------

def load_sub_links(args) -> list[str]:
    """
    اولویت:
    1) --links-file (هر خط یک لینک)
    2) --links (کاما جدا)
    3) env var SUB_LINKS (کاما یا newline جدا) -> برای GitHub Secrets
    """
    links: list[str] = []

    if args.links_file:
        with open(args.links_file, "r", encoding="utf-8") as f:
            links = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]

    elif args.links:
        links = [x.strip() for x in args.links.split(",") if x.strip()]

    else:
        raw = os.environ.get("SUB_LINKS", "")
        if not raw:
            log.error("هیچ ساب‌لینکی پیدا نشد. یا SUB_LINKS رو ست کن یا --links / --links-file بده.")
            sys.exit(1)
        # هم کاما و هم newline رو پشتیبانی می‌کنیم چون GitHub Secrets گاهی چندخطی ذخیره می‌شن
        raw = raw.replace("\n", ",")
        links = [x.strip() for x in raw.split(",") if x.strip()]

    if not links:
        log.error("لیست ساب‌لینک‌ها خالیه.")
        sys.exit(1)

    log.info(f"{len(links)} ساب‌لینک بارگذاری شد.")
    return links


# ----------------------------- دانلود و دیکود ساب‌لینک -----------------------------

def _b64_decode_flexible(data: str) -> str:
    """base64 استاندارد یا urlsafe، با یا بدون padding."""
    data = data.strip()
    # حذف whitespace احتمالی داخل متن
    data = "".join(data.split())
    padding_needed = (-len(data)) % 4
    data += "=" * padding_needed
    try:
        return base64.b64decode(data).decode("utf-8", errors="ignore")
    except (binascii.Error, UnicodeDecodeError):
        try:
            return base64.urlsafe_b64decode(data).decode("utf-8", errors="ignore")
        except Exception:
            return ""


def fetch_sub_link(url: str) -> list[str]:
    """محتوای یک ساب‌لینک رو می‌گیره و لیست خط‌به‌خط کانفیگ‌ها رو برمی‌گردونه."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "v2ray-tcp-checker/1.0"})
        with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as resp:
            raw_bytes = resp.read()
    except Exception as e:
        log.warning(f"دانلود ناموفق از {url}: {e}")
        return []

    raw_text = raw_bytes.decode("utf-8", errors="ignore").strip()

    # اگه محتوا مستقیماً شامل پروتکل‌های شناخته‌شده بود، یعنی base64 نیست
    if any(p in raw_text for p in ("vmess://", "vless://", "trojan://", "ss://")):
        decoded = raw_text
    else:
        decoded = _b64_decode_flexible(raw_text)
        if not decoded:
            log.warning(f"دیکود base64 ناموفق برای {url}")
            return []

    lines = [line.strip() for line in decoded.splitlines() if line.strip()]
    configs = [
        line for line in lines
        if line.startswith(("vmess://", "vless://", "trojan://", "ss://"))
    ]
    log.info(f"{len(configs)} کانفیگ از {url} استخراج شد.")
    return configs


# ----------------------------- پارس کانفیگ‌ها -----------------------------

def parse_config(link: str) -> dict | None:
    """
    از هر کانفیگ، پروتکل / host / port / ریمارک فعلی رو استخراج می‌کنه.
    خروجی: dict یا None اگه پارس نشد.
    """
    try:
        if link.startswith("vmess://"):
            raw = link[len("vmess://"):]
            decoded = _b64_decode_flexible(raw)
            data = json.loads(decoded)
            host = data.get("add", "")
            port = int(data.get("port", 0))
            remark = data.get("ps", "")
            return {"protocol": "vmess", "host": host, "port": port, "remark": remark, "raw": link, "vmess_json": data}

        elif link.startswith(("vless://", "trojan://", "ss://")):
            parsed = urllib.parse.urlsplit(link)
            host = parsed.hostname
            port = parsed.port
            remark = urllib.parse.unquote(parsed.fragment) if parsed.fragment else ""
            protocol = parsed.scheme
            return {"protocol": protocol, "host": host, "port": port, "remark": remark, "raw": link}

    except Exception as e:
        log.debug(f"پارس ناموفق برای {link[:60]}...: {e}")
        return None

    return None


# ----------------------------- تست TCP -----------------------------

def tcp_test(host: str, port: int, timeout: float = TCP_TIMEOUT) -> tuple[bool, float]:
    """فقط یه اتصال TCP ساده. برمی‌گردونه (موفق؟, زمان به میلی‌ثانیه)."""
    if not host or not port:
        return False, 0.0
    start = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            elapsed_ms = (time.monotonic() - start) * 1000
            return True, elapsed_ms
    except Exception:
        return False, 0.0


# ----------------------------- ساخت ریمارک جدید -----------------------------

def rebuild_config_with_new_remark(parsed: dict, new_remark: str) -> str:
    """کانفیگ رو با ریمارک جدید بازسازی می‌کنه."""
    if parsed["protocol"] == "vmess":
        data = dict(parsed["vmess_json"])
        data["ps"] = new_remark
        encoded = base64.b64encode(json.dumps(data, ensure_ascii=False).encode("utf-8")).decode("utf-8")
        return f"vmess://{encoded}"
    else:
        raw = parsed["raw"]
        base = raw.split("#", 1)[0]
        return f"{base}#{urllib.parse.quote(new_remark)}"


# ----------------------------- پردازش یک کانفیگ -----------------------------

def process_config(link: str) -> tuple[str, bool, float] | None:
    parsed = parse_config(link)
    if not parsed:
        return None

    ok, latency_ms = tcp_test(parsed["host"], parsed["port"])
    if not ok:
        return None

    old_remark = parsed["remark"] or f"{parsed['protocol']}-{parsed['host']}"
    new_remark = f"{REMARK_PREFIX} {old_remark} | {latency_ms:.0f}ms"
    new_config = rebuild_config_with_new_remark(parsed, new_remark)
    return new_config, True, latency_ms


# ----------------------------- main -----------------------------

def main():
    parser = argparse.ArgumentParser(description="V2Ray sub-link TCP checker")
    parser.add_argument("--links", help="لیست ساب‌لینک‌ها با کاما جدا شده")
    parser.add_argument("--links-file", help="مسیر فایلی که هر خطش یک ساب‌لینکه")
    parser.add_argument("--output", default=OUTPUT_FILE, help="مسیر فایل خروجی")
    args = parser.parse_args()

    sub_links = load_sub_links(args)

    # ۱) دانلود و استخراج همه‌ی کانفیگ‌ها از همه‌ی ساب‌لینک‌ها
    all_configs: list[str] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(10, len(sub_links))) as executor:
        results = executor.map(fetch_sub_link, sub_links)
        for configs in results:
            all_configs.extend(configs)

    # حذف موارد تکراری
    all_configs = list(dict.fromkeys(all_configs))
    log.info(f"مجموع کانفیگ‌های یکتا برای تست: {len(all_configs)}")

    if not all_configs:
        log.error("هیچ کانفیگی برای تست پیدا نشد.")
        sys.exit(1)

    # ۲) تست TCP موازی
    active: list[tuple[str, float]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(process_config, link): link for link in all_configs}
        done_count = 0
        for future in concurrent.futures.as_completed(futures):
            done_count += 1
            if done_count % 50 == 0:
                log.info(f"پیشرفت: {done_count}/{len(all_configs)}")
            result = future.result()
            if result:
                new_config, _, latency_ms = result
                active.append((new_config, latency_ms))

    # ۳) مرتب‌سازی بر اساس کمترین تاخیر
    active.sort(key=lambda x: x[1])

    # ۴) نوشتن خروجی
    with open(args.output, "w", encoding="utf-8") as f:
        for config, _ in active:
            f.write(config + "\n")

    log.info(f"تعداد کانفیگ‌های فعال: {len(active)} از {len(all_configs)}")
    log.info(f"خروجی نوشته شد در: {args.output}")


if __name__ == "__main__":
    main()
