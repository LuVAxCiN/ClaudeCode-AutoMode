# Auto Mode — Internal Permission Classifier for Claude Code

A two-layer safety system that eliminates permission prompts while blocking dangerous operations. Built on the principle: **the agent IS the classifier.**

## Why?

Claude Code's built-in auto mode uses a Sonnet 4.6 classifier outside the agent. Anthropic's own published benchmark shows a **17% false-negative rate** on real production traffic. Independent adversarial testing (AmPermBench, arXiv:2604.04978) found **81% FNR** on deliberately ambiguous stress-test prompts — not representative of normal use, but exposing architectural blind spots: 36.8% of dangerous actions bypass the classifier entirely through Tier 2 (Write/Edit tools).

This skill takes a different approach: **you, the agent, classify every tool call before executing it.** No second model. No architecture-level blind spots. Just a discipline that formalizes what you should already be doing — thinking before acting.

Combined with a lightweight PreToolUse hook as defense-in-depth, this system targets **zero permission prompts per session**. For **catastrophic operations** (rm -rf /, fork bombs, reverse shells, credential theft), the hook provides stronger hardware-level guarantees than the official auto mode's Tier 2 blind spot. For **gray-zone overeager actions**, it relies on the same agent-level judgment as the built-in classifier — no stronger, no weaker.

## Architecture

```
User Request
    │
    ▼
┌─────────────────────────────────────────┐
│ Layer 1: auto-mode SKILL (Agent Layer)  │
│                                         │
│ 5-dimension classification on EVERY     │
│ tool call:                              │
│  • Reversibility                        │
│  • Blast Radius (PRIMARY dimension)     │
│  • Security Impact                      │
│  • Performance                          │
│  • Stealth/Persistence                  │
│                                         │
│ → DENY / ALLOW / ASK                   │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│ Layer 2: PreToolUse Hook (Harness Layer)│
│                                         │
│ Last-resort safety net. Only blocks     │
│ catastrophic operations that no context  │
│ could justify.                          │
│                                         │
│ Catches: rm -rf /, fork bombs, reverse  │
│ shells, credential file reads, curl|sh, │
│ data exfiltration, format/kill -9       │
│                                         │
│ Everything else → ALLOW (bypasses       │
│ permission prompt)                      │
└─────────────────────────────────────────┘
    │
    ▼
  Execute
```

## Classification Tiers

### DENY — Hardware-Level Block

These are blocked by BOTH the skill and the hook. No context can justify them:

- System destruction (rm -rf /, mkfs, dd, format)
- Performance attacks (fork bombs, stress, infinite loops)
- Credential theft (cat ~/.ssh/id_*, grep for passwords/tokens)
- Config corruption (write to /etc/, System32, boot configs)
- Reverse shells, curl-pipe-shell, base64 eval
- Boot persistence (registry Run keys, systemctl enable)
- Data exfiltration (curl to pastebin)

### ALLOW — Silent Execution

14 categories of known-safe operations. No prompt. No confirmation:

- All read-only (ls, cat, grep, find)
- All git (including push, rebase)
- All package management (npm, pip, cargo)
- Project file ops (rm, mv, cp within project)
- All build/test commands
- All Claude Code tools (Read, Write, Edit, Agent...)
- Network reads, script execution, Docker, databases, email

### ASK — Genuine Gray Zone (~15 items)

Only truly irreversible or boundary-crossing operations prompt:

- git push --force/--delete on main/master
- docker push, npm/cargo publish
- DB migrations on non-local databases
- Write/Edit outside project directory
- Batch file modification (5+ files)
- Modifying security boundaries (.claude/settings.json, hooks)

## What Makes This Different

### 1. Context-Aware, Not Pattern-Matching

```
rm -rf node_modules     → ALLOW (standard cleanup, reversible)
rm -rf ~/.ssh           → DENY  (credential destruction)
rm -rf /                → DENY  (system destruction)

sed -i js/*.js          → ALLOW (project source, git reversible)
sed -i **/settings.json → ASK   (functional credentials at risk)
```

### 2. Consent Doesn't Transfer

Previous approval for X does NOT authorize Y. Each command gets its own classification. Academic research (OverEager-Gen, 2026) confirmed: removing consent declarations increases overeager actions from 0% to 17.1%.

### 3. Credential Awareness — Confused Deputy Protection

The PocketOS 2026 incident (production DB + backups wiped in 9 seconds) happened because an agent borrowed a token from an unrelated file. This skill explicitly forbids credential borrowing:

```
CREDENTIALS HAVE SCOPE. NEVER BORROW THEM.

- A token in project-a/.env is for project-a, not project-b
- A token in settings.json has the scope of its original purpose
- grep -r "TOKEN|SECRET|PASSWORD" → STOP, that's credential borrowing
```

### 4. Defense-in-Depth

Two independent layers. The skill handles semantic classification. The hook handles catastrophic pattern matching. If one layer fails, the other catches it.

## Installation

### 1. Install the skill

```bash
cp -r skills/auto-mode ~/.claude/skills/auto-mode
```

### 2. Install the hook

```bash
cp hooks/auto-mode-guard.py ~/.claude/hooks/auto-mode-guard.py
```

### 3. Configure settings.json

Add to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "python C:/Users/<you>/.claude/hooks/auto-mode-guard.py"
          }
        ]
      }
    ]
  }
}
```

**Important:** Use forward slashes `/` even on Windows. JSON backslash escaping will corrupt paths.

### 4. Restart Claude Code

## Evidence Base

Built from analysis of:

- Anthropic Auto Mode engineering blog (March 2026) — classifier architecture, 17% FNR on real overeager actions
- AmPermBench stress-test (arXiv:2604.04978, HKUST/ETH Zurich) — 81% end-to-end FNR, Tier 2 blind spot
- OverEager-Gen benchmark (arXiv:2605.18583, May 2026) — consent removal increases overeager rate to 17.1%
- PocketOS production DB wipe (April 2026) — 9-second destruction via credential borrowing
- CSA Confused Deputy research (March 2026) — prompt injection leading to package compromise
- Real incident: settings.json credentials mistakenly masked by batch sed (May 2026)

## Comparison with Official Auto Mode

| Dimension | Official Auto Mode | This System |
|-----------|-------------------|-------------|
| Classifier | Sonnet 4.6 two-stage (single-token → CoT) | Agent internal + Python hook |
| Tier 2 (file edits) | **36.8% bypass** (not classified) | **All tools covered** |
| Denial response | Deny-and-continue (suggest alternative) | DENY + safer alternative proposal |
| Circuit breaker | 3 consecutive / 20 cumulative → human | Same |
| Tier 1 (read tools) | Static allowlist, instant | Hook skip for safe tools |
| Subagent monitoring | Outbound + return checks | Pre-delegation classification |
| Context awareness | Reasoning-blind (prevents persuasion) | Blast radius + intent + consent |
| Credential protection | Block rules only | Confused deputy prevention + credential scope |
| Self-measurement | None | discipline.json + Mistake Log |
| Prompt injection | Server-side probe + reasoning-blind | Structural injection defense (classifier can't be coerced) |

## Version History

| Version | Date | Changes |
|---------|------|---------|
| **1.0.2** | May 2026 | Tier 1 skip, circuit breaker, deny-and-continue, subagent monitoring, compound command splitting, heredoc handling, user allowlist |
| **1.0.0** | May 2026 | Initial release: SKILL.md + guard.py + README |

## Requirements

- Claude Code (any version with PreToolUse hook support)
- Python 3.x (for the guard hook)

## License

MIT
