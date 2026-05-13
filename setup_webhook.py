"""
setup_webhook.py — One-shot script to:
1. Start ngrok HTTP tunnel on port 8000 (free, no account needed)
2. Register the tunnel URL as the Telegram webhook with secret token

Usage:
    python setup_webhook.py

Requirements:
    pip install pyngrok python-dotenv
    (pyngrok downloads ngrok binary automatically)

ngrok free tier: 1 tunnel, new URL on each restart — re-run this script
whenever the container restarts.
"""

import os
import time
import httpx
from dotenv import load_dotenv

load_dotenv()

BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
SECRET    = os.getenv("TELEGRAM_WEBHOOK_SECRET", "umeagleeye_webhook_secret_2024")
PORT      = 8000

if not BOT_TOKEN:
    print("❌ TELEGRAM_BOT_TOKEN not set in .env")
    exit(1)

print("📡 Starting ngrok tunnel …")
try:
    from pyngrok import ngrok
except ImportError:
    print("❌ pyngrok not installed. Run: pip install pyngrok")
    exit(1)

tunnel = ngrok.connect(PORT, "http")
public_url: str = tunnel.public_url  # type: ignore
webhook_url = f"{public_url}/api/v1/telegram/webhook"
print(f"✅ ngrok tunnel: {public_url}")
print(f"🔗 Webhook URL:  {webhook_url}")

# Register with Telegram
time.sleep(1)
resp = httpx.post(
    f"https://api.telegram.org/bot{BOT_TOKEN}/setWebhook",
    json={
        "url":          webhook_url,
        "secret_token": SECRET,
        "allowed_updates": ["message", "callback_query"],
        "drop_pending_updates": True,
    },
    timeout=15,
)
data = resp.json()
if data.get("ok"):
    print(f"✅ Webhook registered successfully!")
    print(f"   URL: {webhook_url}")
else:
    print(f"❌ Webhook registration failed: {data}")
    exit(1)

# Write the URL to .env for reference
env_path = os.path.join(os.path.dirname(__file__), ".env")
lines = open(env_path).readlines()
with open(env_path, "w") as f:
    for line in lines:
        if line.startswith("TELEGRAM_WEBHOOK_URL="):
            f.write(f"TELEGRAM_WEBHOOK_URL={webhook_url}\n")
        else:
            f.write(line)

print(f"\n🟢 Bot is live! Send /start to your bot in Telegram.")
print("   Press Ctrl+C to stop the tunnel.")
print("   NOTE: The URL changes every restart — re-run this script.\n")

try:
    while True:
        time.sleep(60)
except KeyboardInterrupt:
    ngrok.disconnect(tunnel.public_url)
    print("\n🛑 ngrok tunnel closed.")
