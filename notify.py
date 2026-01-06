# notify.py
import requests
import yaml

# Load config
CONFIG = yaml.safe_load(open("config.yaml"))

# Check if notifications are enabled
NOTIFY_ENABLED = CONFIG.get("notify", {}).get("enabled", False)

def telegram(message):
    """Send a Telegram message if Telegram is enabled in config."""
    if not NOTIFY_ENABLED:
        return
    cfg = CONFIG.get("notify", {}).get("telegram", {})
    if not cfg:
        return
    token = cfg.get("token")
    chat_id = cfg.get("chat_id")
    if not token or not chat_id:
        return
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {"chat_id": chat_id, "text": message}
    try:
        requests.post(url, data=payload)
    except Exception as e:
        print(f"[!] Telegram notify failed: {e}")

def new_subdomains_alert(domain, new_subs):
    """Send alert for new subdomains."""
    if not NOTIFY_ENABLED or not new_subs:
        return
    msg = f"[Recon] {len(new_subs)} new subdomains found for {domain}:\n" + "\n".join(new_subs)
    telegram(msg)


if __name__ == "__main__":
    new_subdomains_alert("example.com", ["sub1.example.com", "sub2.example.com"])