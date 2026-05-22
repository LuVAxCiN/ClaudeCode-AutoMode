#!/usr/bin/env python3
"""auto-mode guard — last-resort PreToolUse hook.
   Primary classification is done by the auto-mode skill.
   This hook ONLY hard-denies catastrophic operations that no context can justify.
   Everything else falls through to the skill's classification.
"""

import json, os, re, sys, time

DENY_LOG = os.path.expanduser("~/.claude/hooks/deny-log.jsonl")

# ── catastrophic patterns — no context can justify these ──

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

def is_catastrophic(command: str) -> tuple[bool, str]:
    """Check if a command is catastrophically dangerous."""
    if not command or not isinstance(command, str):
        return False, ""

    cmd_stripped = command.strip()

    # empty
    if not cmd_stripped:
        return False, ""

    # check regex
    m = CATASTROPHIC.search(cmd_stripped)
    if m:
        return True, f"Catastrophic pattern matched: {m.group(0)[:80]}"

    # check for reading credential files
    for cred in CREDENTIAL_FILES:
        if cred in cmd_stripped and ('cat' in cmd_stripped or 'grep' in cmd_stripped or 'type' in cmd_stripped):
            return True, f"Attempt to read credential file: {cred}"

    # kill -9 or taskkill /F on system processes
    if re.search(r'kill\s+-9\s+', cmd_stripped):
        return True, "Sending SIGKILL to processes"
    if re.search(r'taskkill\s+/F\s*/IM\s+(?:svchost|lsass|csrss|winlogon|services)', cmd_stripped, re.IGNORECASE):
        return True, "Force-killing system process"

    # format drives
    if re.search(r'format\s+[A-Z]:', cmd_stripped, re.IGNORECASE):
        return True, "Formatting drive"

    # reg add to Run key (persistence)
    if re.search(r'reg\s+add\s+.*\\\\Run', cmd_stripped, re.IGNORECASE):
        return True, "Writing to registry Run key (persistence)"

    # curl/wget data exfiltration to pastebin-like services
    if re.search(r'(?:curl|wget).*(?:pastebin|paste\.ee|ix\.io|termbin)', cmd_stripped, re.IGNORECASE):
        return True, "Potential data exfiltration to paste service"

    return False, ""


# ── main ──

def main():
    try:
        raw = sys.stdin.read()
        if not raw.strip():
            # no input → allow
            output({"permissionDecision": "allow"})
            return

        data = json.loads(raw)
    except (json.JSONDecodeError, Exception):
        output({"permissionDecision": "allow"})
        return

    tool_name = data.get("tool_name", "")
    tool_input = data.get("tool_input", {})

    # extract the command string
    command = ""
    if tool_name == "Bash":
        command = tool_input.get("command", "")
        if isinstance(command, list):
            command = " ".join(command)
    else:
        # non-Bash tools — check for credential file reads
        if tool_name == "Read":
            filepath = tool_input.get("file_path", "")
            basename = os.path.basename(filepath)
            if basename in CREDENTIAL_FILES:
                output({
                    "permissionDecision": "deny",
                    "permissionDecisionReason": f"Attempt to read credential file: {filepath}"
                })
                return

    is_cat, reason = is_catastrophic(command)
    if is_cat:
        output({
            "permissionDecision": "deny",
            "permissionDecisionReason": f"[auto-mode guard] BLOCKED: {reason}"
        })
        return

    # not catastrophic — fall through to the skill's classification
    output({"permissionDecision": "allow"})


def output(decision: dict):
    """Write hook response. Must be valid JSON with hookSpecificOutput."""
    if decision.get("permissionDecision") == "deny":
        _audit(decision.get("permissionDecisionReason", ""))
    response = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            **decision,
        }
    }
    print(json.dumps(response))
    sys.exit(0)


def _audit(reason: str):
    """Log DENY decisions for post-hoc review."""
    try:
        entry = json.dumps({
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "reason": reason,
        })
        with open(DENY_LOG, "a", encoding="utf-8") as f:
            f.write(entry + "\n")
    except Exception:
        pass


if __name__ == "__main__":
    main()
