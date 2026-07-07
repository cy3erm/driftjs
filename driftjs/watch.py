import json
import time
import urllib.request
from datetime import datetime


def notify_webhook(url, text, timeout=15):
    if "discord" in url:
        payload = {"content": text[:1900]}
    elif "slack" in url or "hooks.slack" in url:
        payload = {"text": text[:3000]}
    else:
        payload = {"text": text[:3000]}
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data,
                                 headers={"Content-Type": "application/json",
                                          "User-Agent": "driftjs"})
    try:
        with urllib.request.urlopen(req, timeout=timeout):
            return True
    except Exception:
        return False


def format_alert(target, new_endpoints, new_secrets, new_weaknesses):
    lines = [f"driftjs: changes on {target}"]
    if new_endpoints:
        lines.append(f"\nNew endpoints ({len(new_endpoints)}):")
        lines += [f"  + {e}" for e in new_endpoints[:25]]
    if new_secrets:
        lines.append(f"\nNew secrets ({len(new_secrets)}):")
        lines += [f"  ! {label}: {red}" for label, red in new_secrets[:15]]
    if new_weaknesses:
        lines.append(f"\nNew weaknesses ({len(new_weaknesses)}):")
        lines += [f"  [{sev}] {label}" for sev, label in new_weaknesses[:15]]
    return "\n".join(lines)


def sleep_with_stamp(interval):
    nxt = datetime.now().timestamp() + interval
    when = datetime.fromtimestamp(nxt).strftime("%H:%M:%S")
    return when, lambda: time.sleep(interval)
