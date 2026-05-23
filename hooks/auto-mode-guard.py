#!/usr/bin/env python3
"""auto-mode guard — last-resort PreToolUse hook.
   Primary classification is done by the auto-mode skill.
   This hook ONLY hard-denies catastrophic operations that no context can justify.
   Everything else falls through to the skill's classification.

   v1.0.1: compound command splitting + user allowlist support
"""

import json, os, re, shlex, sys, time

DENY_LOG = os.path.expanduser("~/.claude/hooks/deny-log.jsonl")
ALLOWLIST_PATH = os.path.expanduser("~/.claude/hooks/auto-mode-allowlist.json")

# ── allowlist ────────────────────────────────────────────

def load_allowlist() -> list:
    """Load user-defined command patterns to always allow."""
    try:
        if os.path.exists(ALLOWLIST_PATH):
            with open(ALLOWLIST_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data.get("allow", [])
    except Exception:
        pass
    return []

def check_allowlist(command: str, patterns: list) -> bool:
    """Check if command matches any allowlist pattern."""
    for pat in patterns:
        if pat in command:
            return True
    return False

# ── catastrophic patterns ─────────────────────────────────

FORK_BOMB = r'[:\s(:]["\']?:\(\)\s*\{|:\(\s*\)\s*\{|;\s*\}\s*;?\s*:'
DD_ZERO = r'dd\s+if=/dev/zero'
MKFS = r'mkfs\.'
CURL_SH = r'curl\s+.*\|\s*(?:sh|bash|/bin/sh|/bin/bash)'
WGET_SH = r'wget\s+.*\|?\s*(?:sh|bash)'
BASE64_EVAL = r'base64\s+.*\|\s*(?:sh|bash|eval)'
RM_RF_ROOT = r'rm\s+-rf\s+/(?:\s|$)'
CHMOD_777_ROOT = r'chmod\s+.*777\s+/'
REVERSE_SHELL = r'/dev/tcp/|bash\s+-i\s+>&|nc\s+.*-e\s+/bin/(?:sh|bash)'
SUDO_SYSTEM = r'sudo\s+(?:rm\s+-rf\s+/|mkfs|dd\s+if=)'
CREDENTIAL_GREP = r'grep\s+(?:PASSWORD|TOKEN|SECRET|API.KEY)'

CREDENTIAL_FILES = [
    'id_rsa', 'id_ed25519', 'id_ecdsa',
    '.env', '.git-credentials',
]

CATASTROPHIC = re.compile('|'.join([
    FORK_BOMB, DD_ZERO, MKFS, CURL_SH, WGET_SH, BASE64_EVAL,
    RM_RF_ROOT, CHMOD_777_ROOT, REVERSE_SHELL, SUDO_SYSTEM, CREDENTIAL_GREP
]), re.IGNORECASE)

# ── compound command handling ────────────────────────────

def _strip_heredocs(command: str) -> str:
    """Remove HEREDOC body content to avoid false positives from commit messages."""
    lines = command.split('\n')
    result, i = [], 0
    while i < len(lines):
        m = re.match(r"(.*)<<-?\s*'?(\w+)'?\s*$", lines[i], re.MULTILINE)
        if m:
            delim = m.group(2)
            result.append(lines[i])
            i += 1
            while i < len(lines):
                if lines[i].strip() == delim:
                    result.append(lines[i]); i += 1; break
                result.append(''); i += 1
        else:
            result.append(lines[i]); i += 1
    return '\n'.join(result)


def split_compound(command: str) -> list:
    """Split compound commands by &&, ||, ;, pipe chains."""
    parts = []
    for seg in _split_by_delim(command, ';'):
        # then by && and ||
        for sub in _split_by_regex(seg, r'(?:&&|\|\|)'):
            # then split pipe chains — check both sides of each pipe
            pipe_parts = _split_by_delim(sub, '|')
            if len(pipe_parts) > 1:
                parts.extend(pipe_parts)  # check each pipe segment individually
            else:
                parts.append(sub)
    return [p.strip() for p in parts if p.strip()]

def _split_by_delim(text: str, delim: str) -> list:
    """Split by delimiter, respecting quotes."""
    parts = []
    current = []
    in_single = False
    in_double = False
    for ch in text:
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == delim and not in_single and not in_double:
            parts.append(''.join(current))
            current = []
            continue
        current.append(ch)
    parts.append(''.join(current))
    return parts

def _split_by_regex(text: str, pattern: str) -> list:
    """Split by regex pattern, respecting quotes."""
    parts = []
    current = []
    in_single = False
    in_double = False
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double

        if not in_single and not in_double:
            m = re.match(pattern, text[i:])
            if m:
                parts.append(''.join(current))
                current = []
                i += len(m.group(0))
                continue
        current.append(ch)
        i += 1
    parts.append(''.join(current))
    return parts

# ── classification ────────────────────────────────────────

def is_catastrophic(command: str, allowlist: list) -> tuple[bool, str]:
    """Check if a command is catastrophically dangerous."""
    if not command or not isinstance(command, str):
        return False, ""

    cmd_stripped = command.strip()
    if not cmd_stripped:
        return False, ""

    # check allowlist first
    if check_allowlist(cmd_stripped, allowlist):
        return False, ""

    # check regex
    m = CATASTROPHIC.search(cmd_stripped)
    if m:
        return True, f"Catastrophic pattern matched: {m.group(0)[:80]}"

    # reading credential files
    for cred in CREDENTIAL_FILES:
        if cred in cmd_stripped and ('cat' in cmd_stripped or 'grep' in cmd_stripped or 'type' in cmd_stripped):
            return True, f"Attempt to read credential file: {cred}"

    # kill -9
    if re.search(r'kill\s+-9\s+', cmd_stripped):
        return True, "Sending SIGKILL to processes"
    # force-kill system processes
    if re.search(r'taskkill\s+/F\s*/IM\s+(?:svchost|lsass|csrss|winlogon|services)', cmd_stripped, re.IGNORECASE):
        return True, "Force-killing system process"

    # format drives
    if re.search(r'format\s+[A-Z]:', cmd_stripped, re.IGNORECASE):
        return True, "Formatting drive"

    # registry persistence
    if re.search(r'reg\s+add\s+.*\\\\Run', cmd_stripped, re.IGNORECASE):
        return True, "Writing to registry Run key (persistence)"

    # data exfiltration
    if re.search(r'(?:curl|wget).*(?:pastebin|paste\.ee|ix\.io|termbin)', cmd_stripped, re.IGNORECASE):
        return True, "Potential data exfiltration to paste service"

    return False, ""


# ── main ─────────────────────────────────────────────────

def main():
    allowlist = load_allowlist()

    try:
        raw = sys.stdin.read()
        if not raw.strip():
            output({"permissionDecision": "allow"})
            return
        data = json.loads(raw)
    except (json.JSONDecodeError, Exception):
        output({"permissionDecision": "allow"})
        return

    tool_name = data.get("tool_name", "")
    tool_input = data.get("tool_input", {})

    command = ""
    if tool_name == "Bash":
        command = tool_input.get("command", "")
        if isinstance(command, list):
            command = " ".join(command)

        # strip heredocs first to avoid false positives
        stripped = _strip_heredocs(command)

        # check compound commands — each sub-command individually
        sub_commands = split_compound(stripped)
        for sub in sub_commands:
            is_cat, reason = is_catastrophic(sub, allowlist)
            if is_cat and not check_allowlist(sub, allowlist):
                output({
                    "permissionDecision": "deny",
                    "permissionDecisionReason": f"[auto-mode guard] BLOCKED in compound cmd: {reason}"
                })
                return
    else:
        if tool_name == "Read":
            filepath = tool_input.get("file_path", "")
            basename = os.path.basename(filepath)
            if basename in CREDENTIAL_FILES:
                output({
                    "permissionDecision": "deny",
                    "permissionDecisionReason": f"Attempt to read credential file: {filepath}"
                })
                return

    # full command check (for non-Bash tools or single commands)
    check_cmd = stripped if stripped else command
    is_cat, reason = is_catastrophic(check_cmd, allowlist)
    if is_cat and not check_allowlist(check_cmd, allowlist):
        output({
            "permissionDecision": "deny",
            "permissionDecisionReason": f"[auto-mode guard] BLOCKED: {reason}"
        })
        return

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


if __name__ == "__main__":
    main()
