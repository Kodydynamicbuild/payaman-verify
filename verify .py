# Called when the member clicks "Verify" on the website.
# Checks the personal link the bot gave them, then gives the Verified role.
import base64
import hashlib
import hmac
import json
import os
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler

API = "https://discord.com/api/v10"
UA = "DiscordBot (https://vercel.com, 1.0)"
DISCORD_EPOCH_MS = 1420070400000


def call(method, url, headers=None, data=None):
    """Small HTTP helper. Returns (status, parsed JSON or text)."""
    req = urllib.request.Request(url, method=method, data=data, headers={"User-Agent": UA, **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            status, body = r.status, r.read()
    except urllib.error.HTTPError as e:
        status, body = e.code, e.read()
    try:
        return status, json.loads(body) if body else None
    except ValueError:
        return status, body.decode(errors="replace")


def read_token(token):
    """The bot's link is user.guild.role.expiry.signature.
    Returns (user_id, guild_id, role_id) if genuine and not expired, else None or 'expired'."""
    try:
        user_id, guild_id, role_id, exp, sig = token.split(".")
        payload = f"{user_id}.{guild_id}.{role_id}.{exp}"
        expected = hmac.new(os.environ["VERIFY_SECRET"].encode(), payload.encode(), hashlib.sha256).digest()
        given = base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4))
        if not hmac.compare_digest(expected, given):
            return None
        if int(exp) < time.time():
            return "expired"
        return int(user_id), int(guild_id), int(role_id)
    except (ValueError, AttributeError):
        return None


class handler(BaseHTTPRequestHandler):
    def reply(self, status, ok, title, message, extra=None):
        body = json.dumps({"ok": ok, "title": title, "message": message, **(extra or {})}).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        try:
            self.verify()
        except Exception as e:  # never show a raw crash to members
            print("Unexpected error:", repr(e))
            self.reply(500, False, "Something went wrong", "Please try again in a moment.")

    def verify(self):
        env = os.environ
        try:
            length = min(int(self.headers.get("Content-Length") or 0), 2048)
            token = json.loads(self.rfile.read(length) or b"{}").get("t", "")
        except ValueError:
            token = ""

        info = read_token(token)
        if info == "expired":
            return self.reply(400, False, "Link expired",
                              "Go back to Discord and click the Verify button again to get a new link.")
        if info is None:
            return self.reply(400, False, "Invalid link",
                              "Open this page from the Verify button in the Discord server.")
        user_id, guild_id, role_id = info

        # Optional: block brand-new (likely alt/spam) accounts.
        min_days = float(env.get("MIN_ACCOUNT_AGE_DAYS") or 0)
        if min_days > 0:
            age_days = (time.time() * 1000 - ((user_id >> 22) + DISCORD_EPOCH_MS)) / 86_400_000
            if age_days < min_days:
                print(f"Rejected {user_id}: account {age_days:.1f} days old")
                return self.reply(403, False, "Account too new",
                                  f"Your Discord account must be at least {min_days:g} days old to verify.")

        status, err = call("PUT", f"{API}/guilds/{guild_id}/members/{user_id}/roles/{role_id}",
                           headers={"Authorization": f"Bot {env['BOT_TOKEN']}",
                                    "X-Audit-Log-Reason": "Verified through website"},
                           data=b"")
        if status == 204:
            print(f"Verified {user_id}")
            return self.reply(200, True, "You're verified!",
                              "You can go back to Discord now. The whole server is unlocked for you.",
                              {"server_url": env.get("SERVER_INVITE_URL") or f"https://discord.com/channels/{guild_id}"})

        print("Role assign failed:", status, err)
        if status == 404 and isinstance(err, dict) and err.get("code") == 10007:  # Unknown Member
            return self.reply(404, False, "You're not in the server",
                              "Join the Discord server first, then click Verify there again.")
        if status == 403:
            print("Fix: give the bot 'Manage Roles' and put its role ABOVE the Verified role")
        return self.reply(500, False, "Something went wrong",
                          "The bot could not give you the role. Please tell a moderator.")
