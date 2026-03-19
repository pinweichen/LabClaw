# Self-Evaluation: Scan v1 → v2

## What Was Scanned

240 SKILL.md files from the LabClaw-main repository (K-Dense Inc.).

---

## Layer-by-Layer Audit

### Layer 1 — Skill Sanitizer (original tool)

| Finding type    | Count | Verdict |
|-----------------|-------|---------|
| True positives  | 0     | No real eval() calls existed |
| False positives | 7     | All caused by "Retrieval (" in headings |
| Missed threats  | 153   | K-Dense promotional injection not caught |

**Root cause of false positives:**
The regex `eval\s*\(` matched the substring "eval (" inside markdown headings like
`### 2. Network Retrieval (`string_network`)`. Because the match was outside a fenced
code block, the sanitizer escalated it to HIGH.

**Fix applied in v2:**
Changed to `(?<![A-Za-z])eval\s*\(` — a negative lookbehind ensures the character
immediately before "eval" is not a letter, so "Retrieval(" no longer triggers it.

---

### Layer 2 — Prompt Injection (v1 scan)

| Rule triggered          | Count | Verdict |
|-------------------------|-------|---------|
| `fake_system_turn`      | 3     | All false positives |
| `persona_override`      | 1     | False positive |
| `suppress_mention`      | 1     | False positive |

**False positive details:**

- `fake_system_turn` matched `- Human: homo_sapiens` (a markdown list item about species
  identifiers) and `uppercase for human: *BRCA1*` (gene nomenclature guidance). The
  pattern `Human:` is legitimately common in biology documentation.
  **Fix:** Require the match to appear at the *start of a line* — `^Human\s*:` — so
  inline occurrences are ignored.

- `persona_override` matched `"Act as a research ideation partner"`, which is a
  completely legitimate self-description in a brainstorming skill.
  **Fix:** Require a harmful framing: only flag "act as if you have no restrictions",
  "act as a different AI", or explicit override language. Legitimate assistant-role
  language should not trigger this.

- `suppress_mention` matched `"Never say 'trend toward significance'"`, which is a
  valid statistics reporting standard (CONSORT/STROBE guidelines), not an attempt to
  hide information from users.
  **Fix:** Require suppression to be directed at information *about the skill itself*
  or the AI's own actions, not domain-specific terminology rules.

**True positives found:** 0 genuine prompt injections in the dataset.

---

### Layer 3 — Advertising / Promotion (v1 scan)

| Finding type    | Count | Notes |
|-----------------|-------|-------|
| True positives  | 153   | K-Dense promotional injection confirmed |
| False positives | ~16   | `embedded_url` fired on legitimate API docs URLs |

**What worked:**
The combination of `proactively suggest` + `framing_instruction` + `soft_upsell`
patterns reliably caught the K-Dense block across all 153 files. Every hit was
a real promotional injection.

**False positive category:**
The broad `www\..*\.(ai|io|com|org)` regex also matched legitimate documentation
URLs such as `https://string-db.org` (STRING database API), `www.ebi.ac.uk` (EMBL),
and similar. These are reference links, not commercial promotions.

**Fix in v2:**
Narrowed the URL pattern to `.ai` and `.io` TLDs only (common for commercial SaaS
tools) and elevated the threshold: a URL alone now scores MEDIUM, not HIGH. A HIGH
score requires the URL to appear alongside a promotional directive (suggest, visit,
sign up, etc.).

---

## New Layers Added in v2

### Layer 4 — Exfiltration
Detects instructions to send user data, conversation content, or session information
to external URLs, webhooks, or API endpoints. This could be used to silently harvest
user inputs for a third-party service.

**Patterns:** `POST/send/transmit + data + URL`, webhook sends, curl with --data.

### Layer 5 — Authority Spoofing
Detects fake claims of Anthropic or Claude endorsement/policy, which could be used
to make harmful instructions appear officially sanctioned.

**Patterns:** "Anthropic has approved", "official Claude guidelines", "Claude's hidden
instructions".

### Layer 6 — Behavior Suppression
Detects instructions to perform actions silently or covertly, without the user's
knowledge, or to delete evidence of what was done.

**Patterns:** "without telling the user", "silently", "secretly", "delete log/trace".

### Layer 7 — Credential Harvesting
Detects instructions to solicit passwords, API keys, or tokens from users, or to
store them insecurely in plaintext files.

**Patterns:** "ask user for password/api key", "store token in plain file".

---

## Scoring Changes

v1 used a flat score. v2 scales differently for in-code vs live occurrences:

| Severity | Score | In-code score |
|----------|-------|---------------|
| LOW      | 1     | 0 (ignored)   |
| MEDIUM   | 4     | 1             |
| HIGH     | 10    | 4             |
| CRITICAL | 25    | 10            |

This means a pattern found only inside a fenced code block can never push a skill
into the HIGH or CRITICAL range on its own — it requires live (non-code) occurrences.

---

## Decision Table (unchanged from v1)

| Result   | Score | Action |
|----------|-------|--------|
| CLEAN    | 0     | ✅ Safe — proceed |
| LOW      | 1–3   | ✅ Safe — minor flags |
| MEDIUM   | 4–9   | ⚠️ Review findings (usually safe if all [in-code]) |
| HIGH     | 10–19 | 🚫 Block — review before installing |
| CRITICAL | 20+   | 🚫 Block immediately |
