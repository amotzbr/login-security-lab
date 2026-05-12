"""
config.py

Central configuration file for the demo login system.

This module controls:
- Which hash function is used(HASH_MODE)
- Whice defenses are enabled
- Global group seed and DB dile names.

All other moduls read their behaiover from here.
Changing a value here lets you re-run the same experiment with a different setup.
"""
import os
# ======= Hash mode =======
#HASH_MODE = "argon2id"
HASH_MODE = "sha256_salt"
#HASH_MODE = "bcrypt"

# ======= Seed / group =======
GROUP_SEED = "REDACTED"

# ======= Pepper =======
PEPPER = os.environ.get("PEPPER", "")


# ======= Files =======
USERS_SEED_FILE ="users.json"
USERS_DB_FILE ="users_db.json"

# ======= Defences =======

# ======= TOTP config =======
ENABLE_TOTP = True
TOTP_USERS_COUNT = 5 # How many users will get TOTP?

# ======= Rate limit config =======
ENABLE_RATE_LIMIT = False
MAX_FAILS_PER_USER = 5
WINDOW_SECONDS = 60

# ======= Account Lock config =======
ENABLE_ACCOUNT_LOCK = False
ACCOUNT_LOCK_MAX_FAILS = 5 # Failed attempts before lock
ACCOUNT_LOCK_WINDOW_SECONDS = 300 # Failed attempts counts for last 10 min
ACCOUNT_LOCK_DURATION_SECONDS = 900 # 15 min lock

# ======= CAPTCHA config =======
ENABLE_CAPTCHA = True
CAPTCHA_FAIL_THRESHOLD = 30
CAPTCHA_TOKEN_TTL_SECONDS = 300
