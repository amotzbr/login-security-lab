# Login-Security Lab

A small but complete research lab for measuring how much **password-spraying** and **brute-force** attacks are actually slowed down by classical login defenses: hash function choice, per-user rate-limiting, account lock-out, CAPTCHA, TOTP 2FA and server-side pepper.

Built as the final assignment for *Introduction to Cyber-Space Defense* at The Open University of Israel. Final course grade for this project: **93**.

> All attacks in this repository target a local Flask server I wrote myself, on my own machine. Nothing here is meant for use against systems you do not own.

---

## What this project demonstrates

- A small **Flask login service** with a clean `register` / `login` / `verify-totp` API.
- **Three hash modes** behind a single switch (`HASH_MODE` in `config.py`):
  - `sha256_salt` (insecure baseline)
  - `bcrypt`
  - `argon2id`
- **Pluggable defenses** that can be turned on or off independently:
  - Per-user **rate-limit** (sliding window)
  - **Account lock-out** after N failures
  - **CAPTCHA challenge** above a global failure threshold
  - **TOTP 2FA** for a configurable subset of users
  - Server-side **pepper** (env-var, not in the DB)
- **Two attack scripts**:
  - `brute_force.py` — exhaustive guessing against a single target user.
  - `password_spraying.py` — one popular password tried against many users.
- **Structured JSONL logging** of every register / login attempt, written by the server.
- An **analysis tool** (`tools/analyze_logs.py`) that turns the raw JSONL into per-configuration counters: attempts, successes, rate-limit hits, CAPTCHA challenges, lock-outs.
- A written **research report** (`docs/research-report.pdf`) comparing all configurations side-by-side and discussing real-world implications.

---

## Repository layout

```
.
├── server/
│   ├── server.py          Flask app: /register, /login, /verify-totp
│   ├── auth_security.py   Hashing, salt/pepper, TOTP, common helpers
│   └── config.py          One file controls hash mode and defenses
│
├── attacks/
│   ├── brute_force.py     Targets one user, walks a wordlist
│   └── password_spraying.py  One password against many users
│
├── tools/
│   ├── generate_users.py  Seeds 30 users (10 weak / 10 medium / 10 strong)
│   ├── analyze_logs.py    Summarizes attempts.log JSONL into counters
│   └── data_log.py        Shared logging helpers used by the server
│
├── data/
│   └── 10k-most-common.txt  Wordlist used by the attack scripts
│
└── docs/
    └── research-report.pdf  Full write-up with measurements and conclusions
```

---

## Setup

Requirements: Python 3.10+.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Where `requirements.txt` is:

```
flask
bcrypt
argon2-cffi
pyotp
```

---

## How an experiment is run

1. **Pick a configuration** in `server/config.py`. For example, the bcrypt baseline with no defenses:

   ```python
   HASH_MODE = "bcrypt"
   ENABLE_RATE_LIMIT     = False
   ENABLE_ACCOUNT_LOCK   = False
   ENABLE_CAPTCHA        = False
   ENABLE_TOTP           = False
   PEPPER                = ""        # set via env var to enable
   ```

2. **Seed users.** This creates `users.json` (the cleartext "ground truth" used by the attack scripts) and `users_db.json` (what the server actually stores: hash, salt, mode, TOTP flag):

   ```bash
   python tools/generate_users.py
   ```

3. **Start the server.**

   ```bash
   python server/server.py
   ```

   The server listens on `http://127.0.0.1:5000` and appends one JSON line per attempt to `attempts.log`.

4. **Run an attack** in another terminal:

   ```bash
   python attacks/brute_force.py        # target: a specific user
   python attacks/password_spraying.py  # target: every user, one password at a time
   ```

5. **Analyze the run:**

   ```bash
   python tools/analyze_logs.py attempts.log
   ```

6. **Tweak `config.py`**, wipe `attempts.log`, and re-run to compare configurations.

---

## What was measured

For each combination of `HASH_MODE × DEFENSES × ATTACK`, the report records:

- Total login attempts the attacker managed to send.
- Successful guesses (broken down by password strength bucket).
- Wall-clock time to the first success.
- Defense activations: rate-limit blocks, lock-outs, CAPTCHA challenges, TOTP rejections.

Headline conclusions from the report:

- `sha256+salt` falls in minutes against the 10k wordlist, even with random salts.
- `bcrypt` and `argon2id` change the picture only when **combined** with a rate-limit and lock-out. CPU-cost alone is not a defense once a single attacker can fire thousands of attempts per minute from the same box.
- Server-side **pepper** is cheap, easy and pushes offline-cracking out of reach for a stolen `users_db.json`. There is no good reason not to use it.
- TOTP fully closes the spraying attack for the protected users and is the single biggest jump in difficulty for the attacker.

---

## Security note

This repository is intentionally open. The point of the project is to *show* how attacks behave and how each defense answers them. **Do not point the attack scripts at a server you do not own.**

---

## License

No license is attached. Read the code, learn from the report, but please contact me before reusing it for anything else.

— **Amotz Baruch** · [amotzbr@gmail.com](mailto:amotzbr@gmail.com)
