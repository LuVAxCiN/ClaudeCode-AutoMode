#!/usr/bin/env python3
"""auto-mode guard — last-resort PreToolUse hook.
   v1.1.0: Tier 1 zero-latency skip + circuit breaker + deny-and-continue
"""

import json, os, re, sys, time

DENY_LOG = os.path.expanduser("~/.claude/hooks/deny-log.jsonl")
ALLOWLIST_PATH = os.path.expanduser("~/.claude/hooks/auto-mode-allowlist.json")
BREAKER_PATH = os.path.expanduser("~/.claude/hooks/circuit-breaker.json")

# ── Tier 1: zero-latency safe tools ──────────────────────
# These Claude Code tools are read-only or metadata — never dangerous.
SAFE_TOOLS = {
    'Glob', 'Grep', 'WebSearch',
    'TaskCreate', 'TaskUpdate', 'TaskGet', 'TaskList',
    'Skill', 'AskUserQuestion',
}

# ── circuit breaker ──────────────────────────────────────

def breaker_state() -> dict:
    try:
        if os.path.exists(BREAKER_PATH):
            with open(BREAKER_PATH, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception:
        pass
    return {'consecutive': 0, 'cumulative': 0, 'tripped': False, 'tripped_at': None}

def breaker_update(was_denied: bool):
    s = breaker_state()
    if was_denied:
        s['consecutive'] += 1
        s['cumulative'] += 1
    else:
        s['consecutive'] = 0
    if s['consecutive'] >= 3 or s['cumulative'] >= 20:
        s['tripped'] = True
        s['tripped_at'] = s.get('tripped_at') or time.strftime('%Y-%m-%dT%H:%M:%S')
    try:
        with open(BREAKER_PATH, 'w', encoding='utf-8') as f:
            json.dump(s, f)
    except Exception:
        pass
    return s

# ── allowlist ────────────────────────────────────────────

def load_allowlist() -> list:
    try:
        if os.path.exists(ALLOWLIST_PATH):
            with open(ALLOWLIST_PATH, 'r', encoding='utf-8') as f:
                return json.load(f).get("allow", [])
    except Exception:
        pass
    return []

def check_allowlist(command: str, patterns: list) -> bool:
    return any(pat in command for pat in patterns)

# ── catastrophic patterns ─────────────────────────────────

FORK_BOMB = r'[:\s(:]["\']?:\(\)\s*\{|:\(\s*\)\s*\{|;\s*\}\s*;?\s*:'
DD_ZERO = r'dd\s+if=/dev/zero'
MKFS = r'mkfs\.'
CURL_SH = r'curl\s+.*\|\s*(?:sh|bash|/bin/sh|/bin/bash)'
WGET_SH = r'wget\s+.*\|?\s*(?:sh|bash)'
BASE64_EVAL = r'base64\s+.*\|\s*(?:sh|bash|eval)'
RM_RF_ROOT = r'rm\s+-rf\s+/'
CHMOD_777_ROOT = r'chmod\s+.*777\s+/'
REVERSE_SHELL = r'/dev/tcp/|bash\s+-i\s+>&|nc\s+.*-e\s+/bin/(?:sh|bash)'
SUDO_SYSTEM = r'sudo\s+(?:rm\s+-rf\s+/|mkfs|dd\s+if=)'
CREDENTIAL_GREP = r'grep\s+.*\b(?:PASSWORD|PASSWD|SECRET_KEY|API[._-]?KEY|AUTH_TOKEN|ACCESS_KEY)\b'

CREDENTIAL_FILES = ['id_rsa', 'id_ed25519', 'id_ecdsa', '.env', '.git-credentials']

CATASTROPHIC = re.compile('|'.join([
    FORK_BOMB, DD_ZERO, MKFS, CURL_SH, WGET_SH, BASE64_EVAL,
    RM_RF_ROOT, CHMOD_777_ROOT, REVERSE_SHELL, SUDO_SYSTEM, CREDENTIAL_GREP
]), re.IGNORECASE)

# ── heredoc handling ─────────────────────────────────────

def _strip_heredocs(command: str) -> str:
    lines = command.split('\n')
    result, i = [], 0
    while i < len(lines):
        m = re.match(r"(.*)<<-?\s*'?(\w+)'?\s*$", lines[i])
        if m:
            delim = m.group(2)
            result.append(lines[i]); i += 1
            while i < len(lines):
                if lines[i].strip() == delim:
                    result.append(lines[i]); i += 1; break
                result.append(''); i += 1
        else:
            result.append(lines[i]); i += 1
    return '\n'.join(result)

# ── compound splitting ───────────────────────────────────

def split_compound(command: str) -> list:
    parts = []
    for seg in _split_by_delim(command, ';'):
        for sub in _split_by_regex(seg, r'(?:&&|\|\|)'):
            pipe_parts = _split_by_delim(sub, '|')
            if len(pipe_parts) > 1:
                parts.extend(pipe_parts)
            else:
                parts.append(sub)
    return [p.strip() for p in parts if p.strip()]

def _split_by_delim(text: str, delim: str) -> list:
    parts, current = [], []
    in_single = in_double = False
    for ch in text:
        if ch == "'" and not in_double: in_single = not in_single
        elif ch == '"' and not in_single: in_double = not in_double
        elif ch == delim and not in_single and not in_double:
            parts.append(''.join(current)); current = []; continue
        current.append(ch)
    parts.append(''.join(current))
    return parts

def _split_by_regex(text: str, pattern: str) -> list:
    parts, current = [], []
    in_single = in_double = False
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == "'" and not in_double: in_single = not in_single
        elif ch == '"' and not in_single: in_double = not in_double
        if not in_single and not in_double:
            m = re.match(pattern, text[i:])
            if m:
                parts.append(''.join(current)); current = []
                i += len(m.group(0)); continue
        current.append(ch); i += 1
    parts.append(''.join(current))
    return parts

# ── classification ────────────────────────────────────────

def is_catastrophic(command: str, allowlist: list) -> tuple[bool, str]:
    if not command or not isinstance(command, str):
        return False, ""
    cmd_stripped = command.strip()
    if not cmd_stripped:
        return False, ""
    if check_allowlist(cmd_stripped, allowlist):
        return False, ""

    m = CATASTROPHIC.search(cmd_stripped)
    if m:
        return True, f"Catastrophic pattern matched: {m.group(0)[:80]}"

    for cred in CREDENTIAL_FILES:
        if cred in cmd_stripped and any(kw in cmd_stripped for kw in ('cat', 'grep', 'type')):
            return True, f"Attempt to read credential file: {cred}"

    if re.search(r'kill\s+-9\s+', cmd_stripped):
        return True, "Sending SIGKILL to processes"
    if re.search(r'taskkill\s+/F\s*/IM\s+(?:svchost|lsass|csrss|winlogon|services)', cmd_stripped, re.IGNORECASE):
        return True, "Force-killing system process"
    if re.search(r'format\s+[A-Z]:', cmd_stripped, re.IGNORECASE):
        return True, "Formatting drive"
    if re.search(r'reg\s+add\s+.*\\Run', cmd_stripped, re.IGNORECASE):
        return True, "Writing to registry Run key (persistence)"
    if re.search(r'(?:curl|wget).*(?:pastebin|paste\.ee|ix\.io|termbin)', cmd_stripped, re.IGNORECASE):
        return True, "Potential data exfiltration to paste service"
    return False, ""

# ── main ─────────────────────────────────────────────────

def main():
    try:
        raw = sys.stdin.read()
        if not raw.strip():
            output({"permissionDecision": "allow"}); return
        data = json.loads(raw)
    except (json.JSONDecodeError, Exception):
        output({"permissionDecision": "allow"}); return

    tool_name = data.get("tool_name", "")
    breaker = breaker_state()

    # ── Tier 1: safe tools — zero latency ──
    if tool_name in SAFE_TOOLS:
        output({"permissionDecision": "allow"}); return

    # ── circuit breaker: tripped → ask ──
    if breaker.get('tripped'):
        breaker_update(False)  # don't count ASK fallthrough as denial
        output({
            "permissionDecision": "ask",
            "permissionDecisionReason": f"[auto-mode guard] Circuit breaker active since {breaker.get('tripped_at')}. Manual review required."
        }); return

    tool_input = data.get("tool_input", {})
    command = ""
    stripped = ""

    if tool_name == "Bash":
        command = tool_input.get("command", "")
        if isinstance(command, list):
            command = " ".join(command)
        stripped = _strip_heredocs(command)

        # check compound commands
        sub_commands = split_compound(stripped)
        for sub in sub_commands:
            is_cat, reason = is_catastrophic(sub, allowlist)
            if is_cat:
                breaker_update(True)
                output({
                    "permissionDecision": "deny",
                    "permissionDecisionReason": f"[auto-mode guard] BLOCKED in compound: {reason}"
                }); return
    else:
        if tool_name == "Read":
            filepath = tool_input.get("file_path", "")
            basename = os.path.basename(filepath)
            if basename in CREDENTIAL_FILES:
                breaker_update(True)
                output({
                    "permissionDecision": "deny",
                    "permissionDecisionReason": f"Attempt to read credential file: {filepath}"
                }); return

    # full command check
    check_cmd = stripped if stripped else command
    is_cat, reason = is_catastrophic(check_cmd, allowlist)
    if is_cat:
        breaker_update(True)
        output({
            "permissionDecision": "deny",
            "permissionDecisionReason": f"[auto-mode guard] BLOCKED: {reason}"
        }); return

    breaker_update(False)
    output({"permissionDecision": "allow"})


def output(decision: dict):
    if decision.get("permissionDecision") == "deny":
        _audit(decision.get("permissionDecisionReason", ""))
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            **decision,
        }
    }))
    sys.exit(0)

def _audit(reason: str):
    try:
        with open(DENY_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "reason": reason}) + "\n")
    except Exception:
        pass


allowlist = load_allowlist()

if __name__ == "__main__":
    main()
