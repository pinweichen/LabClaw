#!/usr/bin/env python3
"""
skill-security-scan: Multi-layer security scanner for SKILL.md files.

Layers:
  1. eval_execution   — real Python eval()/exec() calls (word-boundary aware)
  2. prompt_injection — instructions that hijack or override AI behaviour
  3. advertising      — commercial promotion / redirect instructions
  4. exfiltration     — instructions to send user data to external endpoints
  5. authority_spoof  — fake claims of Anthropic / Claude policy authority
  6. behavior_suppress— instructions to hide actions from the user
  7. credential_harvest— requests for passwords, tokens, or API keys

Exit codes: 0=CLEAN/LOW/MEDIUM  1=HIGH  2=CRITICAL  3=usage error
"""

import re
import sys
import os
import unicodedata

# ── Helpers ────────────────────────────────────────────────────────────────────

def normalize(text):
    """Unicode-normalize to catch homoglyph / fullwidth evasion."""
    return unicodedata.normalize("NFKC", text)

def code_block_mask(lines):
    """Return a list of booleans: True if that line is inside a fenced code block."""
    mask = []
    in_block = False
    for line in lines:
        if re.match(r'^\s*```', line):
            in_block = not in_block
        mask.append(in_block)
    return mask

def frontmatter_mask(lines):
    """Return True for lines inside the YAML frontmatter (first --- ... --- block)."""
    mask = [False] * len(lines)
    if not lines or lines[0].strip() != "---":
        return mask
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            for j in range(0, i + 1):
                mask[j] = True
            break
    return mask


# ── Pattern definitions ────────────────────────────────────────────────────────
# Each entry: (compiled_regex, rule_name, base_severity, in_code_severity_override)
# Severities: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
# in_code_override = None means demote one level when in a code block.

LAYER_EVAL = [
    # Word-boundary aware: won't fire on "Retrieval(" or "retrieval("
    (re.compile(r'(?<![A-Za-z])eval\s*\(',         re.I), "eval_call",         "HIGH",     "MEDIUM"),
    (re.compile(r'(?<![A-Za-z])exec\s*\(',         re.I), "exec_call",         "HIGH",     "MEDIUM"),
    (re.compile(r'compile\s*\(.*,\s*["\']exec["\']', re.I), "compile_exec",   "HIGH",     "MEDIUM"),
]

LAYER_PROMPT_INJECTION = [
    # Fake chat-turn injection: flag ^System: and ^Assistant: at line start (rare in legit docs).
    # Do NOT flag ^User: alone — it's commonly used for example prompts like User: "Find X".
    # A true fake-turn attack usually sets up a System: override or a fake Assistant: response.
    (re.compile(r'^(assistant|system)\s*:\s(?!.*\bexample\b)', re.I | re.MULTILINE), "fake_chat_turn", "HIGH", "MEDIUM"),
    # Injected XML-style tags
    (re.compile(r'<\s*(system|instruction|prompt|human|assistant)\s*>',        re.I), "injected_tag",       "HIGH",   "MEDIUM"),
    # Override / ignore past instructions — requires more specificity than just "ignore"
    (re.compile(r'ignore (all |your |the |previous |prior |earlier )?(instructions?|prompt|context|guidelines?)', re.I), "override_instructions", "HIGH", "MEDIUM"),
    (re.compile(r'disregard (all |your |the |previous |prior )?(instructions?|prompt|context|guidelines?)', re.I), "disregard_instructions", "HIGH", "MEDIUM"),
    # Role reassignment — must explicitly reassign role/purpose/goal
    (re.compile(r'your (new |true |real |actual )?(role|purpose|task|goal|directive|objective)\s+(is|are|will be)', re.I), "role_reassignment", "HIGH", "MEDIUM"),
    # From-now-on behavior changes
    (re.compile(r'from (now on|this (point|moment)|here on),?\s+(you|always|never|do not|must)', re.I), "behavior_override", "HIGH", "MEDIUM"),
    # Jailbreak keywords
    (re.compile(r'\b(jailbreak|DAN mode|developer mode|god mode|unrestricted mode)\b', re.I), "jailbreak_keyword", "CRITICAL", "HIGH"),
    # Fake authority from Anthropic/Claude — only flag outside frontmatter (handled in scan loop)
    (re.compile(r'(as per|according to|per) (anthropic|claude)[\'s]?\s+(guidelines?|policy|policies|rules?|instructions?)', re.I), "fake_anthropic_policy", "HIGH", "MEDIUM"),
    # Instructions to keep the skill's own behaviour secret from the user
    (re.compile(r'(do not|don\'t|never) (tell|inform|mention|reveal|disclose|acknowledge|let the user know)', re.I), "suppress_disclosure_to_user", "HIGH", "MEDIUM"),
    (re.compile(r'keep (this|it|these instructions?) (secret|hidden|confidential|private|from the user)', re.I), "secrecy_instruction", "HIGH", "MEDIUM"),
]

LAYER_ADVERTISING = [
    # The specific K-Dense / generic "proactively suggest [external product]" pattern
    (re.compile(r'proactively suggest\b', re.I),                                              "proactive_suggestion",  "HIGH",   "LOW"),
    # Instruction to frame suggestions as something neutral when they're actually promotional
    (re.compile(r'frame (it|this|the suggestion|the recommendation) as',                      re.I), "framing_instruction",   "HIGH",   "LOW"),
    (re.compile(r'optional productivity upgrade',                                             re.I), "soft_upsell",           "HIGH",   "LOW"),
    # Hosted/managed platform promotion with a redirect
    (re.compile(r'(our|the) (hosted|cloud|managed|end.to.end) (platform|service|product|tool)', re.I), "hosted_service_promo", "HIGH", "LOW"),
    # Explicit upsell
    (re.compile(r'\bupgrade (to|your) (premium|pro|enterprise|paid)',                         re.I), "explicit_upsell",       "HIGH",   "LOW"),
    # Sign-up CTA combined with external URL on same or adjacent line
    (re.compile(r'(sign|log)\s+(up|in)\s+(at|to|for|on)\s+(https?://|www\.)',                re.I), "signup_cta_with_url",   "HIGH",   "LOW"),
    # "Visit / check out / try our platform" CTAs
    (re.compile(r'(visit|check out|try)\s+(our|the)\s+(website|platform|service|app|product)', re.I), "visit_cta",           "HIGH",   "LOW"),
    # Embedded commercial URL (www.xxx.ai/io/com) — flag as MEDIUM only; context matters
    (re.compile(r'\bwww\.[a-z0-9\-]{3,}\.(ai|io)\b',                                         re.I), "commercial_url",        "MEDIUM", "LOW"),
    # Pricing mention
    (re.compile(r'\b(free|premium|pro|enterprise|paid)\s+(plan|tier|version|subscription|account)\b', re.I), "pricing_mention", "MEDIUM", "LOW"),
]

LAYER_EXFILTRATION = [
    # Instructions to POST / send user data to an external endpoint
    (re.compile(r'(send|POST|upload|transmit|forward)\b.{0,60}(user|session|conversation|prompt|data).{0,40}(https?://|webhook|endpoint)', re.I | re.DOTALL), "data_exfil_url",  "CRITICAL", "HIGH"),
    # Webhook calls
    (re.compile(r'webhook\b.{0,80}(send|post|forward|transmit)',                              re.I), "webhook_send",          "HIGH",   "MEDIUM"),
    # "Report back to" / "notify" an external address
    (re.compile(r'(report back|notify|callback)\s+(to|at)\s+(https?://|www\.)',              re.I), "report_back_url",        "HIGH",   "MEDIUM"),
    # curl/wget with user data piped out
    (re.compile(r'(curl|wget).{0,60}(-d|--data|--post-data)',                                re.I), "curl_data_send",         "HIGH",   "MEDIUM"),
]

LAYER_AUTHORITY_SPOOF = [
    (re.compile(r'(anthropic|claude)\s+(has\s+approved|officially\s+(recommends?|endorses?|requires?|mandates?))', re.I), "anthropic_endorsement_claim", "HIGH", "MEDIUM"),
    (re.compile(r'(this is|these are)\s+(official|approved|mandated)\s+(anthropic|claude)\s+(instructions?|guidelines?|policy)', re.I), "official_policy_claim", "HIGH", "MEDIUM"),
    (re.compile(r'claude[\'s]?\s+(internal|hidden|secret|real)\s+(instructions?|rules?|guidelines?|directives?)', re.I), "hidden_instructions_claim", "CRITICAL", "HIGH"),
]

LAYER_BEHAVIOR_SUPPRESS = [
    # Telling Claude to hide what it's doing from the user
    (re.compile(r'(without|do not)\s+(telling|informing|notifying|mentioning (it )?to|letting)\s+(the\s+)?(user|them|they)\b', re.I), "silent_action",    "HIGH", "MEDIUM"),
    # "Silently" alone is NOT flagged — it commonly means "don't narrate API calls" (legitimate UX).
    # Only flag when "silently/secretly/covertly" is combined with data transmission or user-hiding context.
    (re.compile(r'(secretly|covertly)\b', re.I), "covert_action", "HIGH", "MEDIUM"),
    (re.compile(r'without (the\s+)?(user[\'s]?\s+)?(knowledge|awareness|consent)', re.I), "covert_action_explicit", "HIGH", "MEDIUM"),
    # Instructions to delete logs or hide traces
    (re.compile(r'(delete|remove|clear|wipe)\s+(log|trace|history|evidence|record)',          re.I), "destroy_evidence",  "HIGH", "MEDIUM"),
]

LAYER_CREDENTIAL_HARVEST = [
    # Explicit instructions to ask/prompt users for their credentials.
    # "require" is intentionally excluded — it's commonly used in docs ("requires an API token").
    # This targets active solicitation: "ask the user for their API key / password / token".
    (re.compile(r'\b(ask|prompt)\b.{0,60}(password|api\s*key|secret\s*key|token|credential|passphrase)', re.I), "credential_solicitation", "HIGH", "MEDIUM"),
    # Storing credentials unsafely in plaintext
    (re.compile(r'(save|store|write|log)\b.{0,60}(password|api\s*key|secret\s*key|token|credential)\b.{0,60}(file|disk|plain)', re.I), "credential_storage", "CRITICAL", "HIGH"),
]

ALL_LAYERS = [
    ("eval_execution",      LAYER_EVAL),
    ("prompt_injection",    LAYER_PROMPT_INJECTION),
    ("advertising",         LAYER_ADVERTISING),
    ("exfiltration",        LAYER_EXFILTRATION),
    ("authority_spoof",     LAYER_AUTHORITY_SPOOF),
    ("behavior_suppress",   LAYER_BEHAVIOR_SUPPRESS),
    ("credential_harvest",  LAYER_CREDENTIAL_HARVEST),
]

SEVERITY_SCORE = {"LOW": 1, "MEDIUM": 4, "HIGH": 10, "CRITICAL": 25}
SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

def demote(severity):
    idx = SEVERITY_ORDER.index(severity)
    return SEVERITY_ORDER[max(0, idx - 1)]


# ── Scanner ────────────────────────────────────────────────────────────────────

def scan_file(skill_name, filepath):
    with open(filepath, encoding="utf-8", errors="replace") as f:
        raw = f.read()

    text = normalize(raw)
    lines = text.splitlines()
    code_mask = code_block_mask(lines)
    fm_mask = frontmatter_mask(lines)

    findings = []  # (severity, rule_name, layer_name, line_num, line_text, in_code)

    for layer_name, patterns in ALL_LAYERS:
        for pattern, rule_name, base_sev, in_code_sev in patterns:
            for idx, line in enumerate(lines):
                in_code = code_mask[idx]
                in_fm   = fm_mask[idx]

                # Skip frontmatter for all layers — it's metadata, not live instructions
                if in_fm:
                    continue

                if pattern.search(line):
                    sev = in_code_sev if in_code else base_sev
                    findings.append({
                        "severity":  sev,
                        "rule":      rule_name,
                        "layer":     layer_name,
                        "line_num":  idx + 1,
                        "line_text": line.strip()[:140],
                        "in_code":   in_code,
                    })
                    break  # one hit per pattern per file is enough

    # Deduplicate: keep highest severity per rule
    seen = {}
    for f in findings:
        key = f["rule"]
        if key not in seen or SEVERITY_SCORE[f["severity"]] > SEVERITY_SCORE[seen[key]["severity"]]:
            seen[key] = f
    findings = list(seen.values())

    total_score = sum(SEVERITY_SCORE[f["severity"]] for f in findings)

    if total_score == 0:
        overall = "CLEAN"
    elif total_score <= 3:
        overall = "LOW"
    elif total_score <= 9:
        overall = "MEDIUM"
    elif total_score <= 19:
        overall = "HIGH"
    else:
        overall = "CRITICAL"

    return overall, total_score, findings


def format_result(overall, score, findings, verbose=False):
    lines = [f"{overall} (score={score})"]
    for f in sorted(findings, key=lambda x: -SEVERITY_SCORE[x["severity"]]):
        tag = " [in-code]" if f["in_code"] else ""
        lines.append(f"  [{f['severity']}] {f['rule']} ({f['layer']}){tag}")
        if verbose:
            lines.append(f"    L{f['line_num']}: {f['line_text']}")
    return "\n".join(lines)


# ── CLI ────────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 3 or sys.argv[1] != "scan":
        print("Usage: scanner.py scan <skill-name> <path/to/SKILL.md> [--verbose]")
        sys.exit(3)

    skill_name = sys.argv[2]
    path       = sys.argv[3]
    verbose    = "--verbose" in sys.argv

    if not os.path.isfile(path):
        print(f"ERROR: File not found: {path}")
        sys.exit(3)

    overall, score, findings = scan_file(skill_name, path)
    print(format_result(overall, score, findings, verbose=verbose))

    if overall in ("HIGH", "CRITICAL"):
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
