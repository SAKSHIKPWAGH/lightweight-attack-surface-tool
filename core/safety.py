"""Safety guardrails: protected targets and an audit trail."""
import getpass
import os
from datetime import datetime

# Large third-party platforms and government/military zones are refused outright.
# If you genuinely own one of these, edit this list consciously.
PROTECTED_DOMAINS = {
    "google.com", "gmail.com", "youtube.com", "microsoft.com", "live.com", "outlook.com",
    "office.com", "apple.com", "amazon.com", "facebook.com", "instagram.com", "whatsapp.com",
    "x.com", "twitter.com", "linkedin.com", "openai.com", "chatgpt.com", "anthropic.com",
    "claude.ai", "github.com", "cloudflare.com", "netflix.com", "paypal.com",
}
PROTECTED_SUFFIXES = (".gov", ".mil", ".gov.in", ".nic.in", ".gov.uk")


def is_protected(target: str) -> bool:
    t = target.lower().rstrip(".")
    if any(t == d or t.endswith("." + d) for d in PROTECTED_DOMAINS):
        return True
    return t.endswith(PROTECTED_SUFFIXES)


def audit(outdir: str, target: str, argv):
    """Append a line to output/audit.log recording who scanned what and when."""
    os.makedirs(outdir, exist_ok=True)
    line = "{} | user={} | target={} | args={}\n".format(
        datetime.now().isoformat(timespec="seconds"), getpass.getuser(), target, " ".join(argv))
    with open(os.path.join(outdir, "audit.log"), "a", encoding="utf-8") as fh:
        fh.write(line)
