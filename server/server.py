"""
serever.py

Flask server that simulates a secure login system
for Brute Force & Password Spraying experiments.

Main features:
* Support for different hash modes(HASH_MODE):
 - sha256_salt
 - bcrypt
 - argon2id

* Configurable protections
 - Rate Limit (user)
 - Account Lock (failures in a slice time window)
 - CAPTCHA (global by failuers in the system)
 - TOTP (2FA-time-based)
 - Pepper (global by environment variable)

* Logging
- Each login/register attempt is written as one JSON line into
  attempts.log (JSONL format)

This file is the System Server that the attack scripts talk to over HTTP
"""
from flask import request, jsonify, Flask
import json
from datetime import datetime, timedelta
from collections import defaultdict
from uuid import uuid4
import time

from auth_security import (
    generate_salt,
    hash_password,
    verify_password,
    is_hash_mode_compatible,
    load_users,
    save_users,
    verify_totp_code
)

from config import (
    HASH_MODE,
    GROUP_SEED,
    ENABLE_RATE_LIMIT,
    MAX_FAILS_PER_USER,
    WINDOW_SECONDS,
    ENABLE_ACCOUNT_LOCK,
    ACCOUNT_LOCK_MAX_FAILS,
    ACCOUNT_LOCK_WINDOW_SECONDS,
    ACCOUNT_LOCK_DURATION_SECONDS,
    CAPTCHA_FAIL_THRESHOLD,
    CAPTCHA_TOKEN_TTL_SECONDS, ENABLE_CAPTCHA, ENABLE_TOTP,
    PEPPER
)

# Every connection attempt wriiten here JSONL format
LOG_FILE = f"attempts.log"

# ======== Defences flags  ========
# Base defeneces configuration (all False by default).
# current_defences() takes this base dict and "overrides"
# the relevant flags according to config.py


BASELINE_DEFENSES = {
    "rate_limit": False,
    "account_lock": False,
    "captcha": False,
    "totp": False,
    "pepper": False

}
def current_defenses() -> dict:
    """
    Returns the correct defense configuration by config.py
    This enters to a log file and specified whice defenses enabled
    """
    return {
        **BASELINE_DEFENSES,
        "rate_limit": ENABLE_RATE_LIMIT,
        "account_lock": ENABLE_ACCOUNT_LOCK,
        "captcha": ENABLE_CAPTCHA,
        "totp": ENABLE_TOTP,
        "pepper": bool(PEPPER)
    }


# ====================================
# ======== Rate limit state ==========
# ====================================
# fail_history[username] -> timestamps list of failuers to spesific user
fail_history = defaultdict(list)


def is_rate_limited(username: str) -> bool:
    """
    Rate Limit check for a specific user\n
    Returns: True if the user had {MAX_FAILS_PER_USER} failuers 
    in a {WINDOW_SECONDS} time\n
    Will always return False if {ENABLE_RATE_LIMIT} = false 
    """
    if not ENABLE_RATE_LIMIT:
        return False

    now = datetime.now()
    # Save only failure attempts from the last window
    recent_fails = [t for t in fail_history[username] if (now - t).total_seconds() <= WINDOW_SECONDS]
    fail_history[username] = recent_fails
    return len(recent_fails) >= MAX_FAILS_PER_USER


def register_rate_limit_failure(username: str) -> None:
    """
    Writes a failure for a user for Rate Limit use
    Saved to fali_history to enable count in a time-sliced window\n
    If {ENABLE_RATE_LIMIT} = False -> do nothing
    :param username: The user to check for Rate Limit
    :return: None
    """
    if not ENABLE_RATE_LIMIT:
        return
    fail_history[username].append(datetime.now())


# ====================================
# ======== Account Lock state ========
# ====================================

# Failurs history for an account(Account lock use)
account_fail_history = defaultdict(list)  # Fails per user
locked_until = {}  # username -> Lock expiration time


def is_account_locked(username: str) -> bool:
    """
    Check if the user is locked
    :param username: User to check
    :return: bool - is an account locked?
    
    If {ENABLE_ACCOUNT_LOCK} = False -> False 
    
    Else: if {locked_until[username]} is a future date -> True
    """
    if not ENABLE_ACCOUNT_LOCK:
        return False
    until = locked_until.get(username)
    if not until:
        return False
    return datetime.now() < until


def register_account_failure(username: str) -> None:
    """
    Failure writing for account lock
    {ACCOUNT_LOCK_WINDOW_SECONDS} - counts failures
    and if greater than ACCOUNT_LOCK_MAX_FAILS lock the user for ACCOUNT_LOCK_DURATION_SECONDS
    :param username: User to write failure for
    :return: None
    """
    if not ENABLE_ACCOUNT_LOCK:
        return
    now = datetime.now()
    account_fail_history[username].append(now)
    # Only failures in window time are saved
    recent = [
        t for t in account_fail_history[username] if (now - t).total_seconds() <= ACCOUNT_LOCK_WINDOW_SECONDS
    ]
    account_fail_history[username] = recent
    # limit passed -> lock user
    if len(recent) >= ACCOUNT_LOCK_MAX_FAILS:
        locked_until[username] = now + timedelta(seconds=ACCOUNT_LOCK_DURATION_SECONDS)

# =================================
# ======== CAPTCHA state ==========
# =================================
# Global counter for faliuers in the system
# When limit passed CAPTCHA is activated
global_fail_count = 0
captcha_active = False

# token -> expires_at (when the token is expaired)
captcha_tokens: dict[str, datetime] = {}


def register_global_failure_for_captcha() -> None:
    """
       Every failed connection attempt increasing the global count
       When pass the limit CAPTCHA is activated\n
       If passed {CAPTCHA_FAIL_THRESHOLD} -> captcha_active = True
       """
    global global_fail_count, captcha_active

    if not ENABLE_CAPTCHA:
        return
    global_fail_count += 1
    if global_fail_count >= CAPTCHA_FAIL_THRESHOLD:
        captcha_active = True


def is_valid_captcha_token(token: str | None) -> bool:
    """
     Validate if the CAPTCHA token is expired
    :param token: Token to check
    :return:
    - True if {ENABLE_CAPTCHA} = False or token is valid and not expired
    - False if the token is missing /invalid/expired
    """
   # If CAPTCHA is off return true (always allow)
    if not ENABLE_CAPTCHA:
        return True  # if not activated, no need to check
    if not token:
        return False
    expires_at = captcha_tokens.get(token)
    if not expires_at:
        return False
    now = datetime.now()
    if now > expires_at:
        # Expired - delete from memmory
        del captcha_tokens[token]
        return False
    return True

# ======================
# ======== Logs ========
# ======================
def log_attempt(username: str,
                result: str,
                hash_mode: str,
                protection_flags: dict,
                start_time: float) -> None:
    """
    Write a login attempt to a log file format JSONL (1 line for each try)

    :param username: The username that attempts login/register
    :param result: Status string - "ok", "bad_password","rate_limit_block"...
    :param hash_mode: Hsh mode type (sha256_salt/bcrypt/argon2id)
    :param protection_flags: Defenses status - comes from current_defenses()
    :param start_time: Start time (for latency calculation
    :return: None
    """
    latency_ms = (time.perf_counter() - start_time) * 1000

    record = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "group_seed": GROUP_SEED,
        "username": username,
        "hash_mode": hash_mode,
        "protection_flags": protection_flags,
        "result": result,
        "latency_ms": round(latency_ms, 2),
    }
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(record) + "\n")


def require_captcha_if_needed(data: dict, username: str, start_time: float) -> tuple[bool, tuple]:
    """
    Checks whether a CAPTCHA is response is required and if needed, build an error response.
    This function is called from the login routes before checking the password.
    If CAPTCHA is not enabled or not yet activated, it does nothing.
    If CAPTCHA is active, it validates the 'captcha_token' in the request payload.
    When the token is missing or invalid, it logs the attempt and returns a ready
    Flask response that the caller should return to the client.
    :param data: Parsed JSON body of the request (must contain 'captcha_token' when CAPTCHA is active).
    :param username: Username being checked used for logging and rate limiting.
    :param start_time: Start time (for latency)
    :return: A tuple (need_response, (resp, status)):
    - need_response (bool):
        * True -> caller must immediately return (resp, status) to the client.
        * False -> CAPTCHA did not block the request, caller should continue normal flow.
    - resp: Flask Response object (or None when need_response is False).
    - status: HTTP status code (or None when need_response is False).
    """
    if not ENABLE_CAPTCHA or not captcha_active:
        return False, (None, None)
    token = data.get("captcha_token")
    if not is_valid_captcha_token(token):
        log_attempt(
            username=username,
            result="captcha_required",
            hash_mode=HASH_MODE,
            protection_flags=current_defenses(),
            start_time=start_time
        )
        resp = jsonify({"error": "captcha_required"})
        return True, (resp, 403)
    return False, (None, None)


def check_required_fields(field_values: dict,
                          missing_reason: str,
                          error_message: str,
                          start_time: float):
    """
    Validate that required JSON fields (for example: username, password, totp_code)
    are present and not empty.

    If at least one field is missing or empty:
        - write a log entry with "missing_reason"
        - return a Flask (Response, 400)

    If all fields are valid:
        - return None and the caller continues normally.

    :param field_values: Dict -> field name : value
    :param missing_reason: Which result is written to the log (example:"missin_fields")
    :param error_message: The error message that will return to the client
    :param start_time: Start time (for logs and latency)
    :return:
        (resp, status) - If something is missing
        None - If all good



       """
    # Input validation
    username = field_values.get("username") or ""
    if any(v is None or v == "" for v in field_values.values()):
        log_attempt(
            username=username,
            result=missing_reason,
            hash_mode=HASH_MODE,
            protection_flags=current_defenses(),
            start_time=start_time
        )
        return jsonify({"error": error_message}), 400
    return None
    # ===================================
    # ======= Security checks ===========
    # ===================================

def run_security_login_checks(username: str, data: dict, start_time: float):
    """Activate all enabled defenses checks
    - CAPTCHA
    - Rate limit
    - Account lock
    - User existence
    :returns (user, None) - when all checks passed
    (None, (resp, status)) - when some checks failed
    """
    # ==========================================
    # ======= CAPTCHA check (if active) ========
    # ==========================================
    need_captcha_resp, (resp, status) = require_captcha_if_needed(data, username, start_time)
    if need_captcha_resp:
        return None, (resp, status)
    #==========================================
    # ======= User existence ==================
    #==========================================
    if username not in users:
        # Mark failure to all mechanisms
        register_rate_limit_failure(username)
        register_global_failure_for_captcha()
        register_account_failure(username)
        log_attempt(
            username=username,
            result="user_not_found",
            hash_mode=HASH_MODE,
            protection_flags=current_defenses(),
            start_time=start_time
        )
        return None, (jsonify({"error": "User not found"}), 404)

    user = users[username]
    # ==========================================
    # ======= Rate limit check  ================
    # ==========================================
    if is_rate_limited(username):
        log_attempt(
            username=username,
            result="rate_limit_block",
            hash_mode=HASH_MODE,
            protection_flags=current_defenses(),
            start_time=start_time
        )
        return None, (jsonify({"error": "Too many attempts please try again later"}), 429)
    # ==========================================
    # ======= Account lock check  ==============
    # ==========================================
    if is_account_locked(username):
        log_attempt(
            username=username,
            result="account_locked",
            hash_mode=HASH_MODE,
            protection_flags=current_defenses(),
            start_time=start_time
        )
        return None, (jsonify({"error": "Account is locked please try again later"}), 423)
    # =========================================
    # ==== Hash mode compatibility check  =====
    # =========================================
    if not is_hash_mode_compatible(user, HASH_MODE):
        log_attempt(
            username=username,
            result="unsupported hash_mode",
            hash_mode=user.get("hash_mode", "unknown"),
            protection_flags=current_defenses(),
            start_time=start_time
        )
        return None, (jsonify({"error": "Unsupported hash_mode"}), 500)
    # ==========================================
    # =========== All checks are ok ============
    # ==========================================
    return user, None


def check_password_and_log(user: dict,
                           username: str,
                           password: str,
                           bad_password_reason: str,
                           start_time: float
                           ):
    """
    Verify the user's password and log a failed attempt if it is incorrect.
    This helper is used by the login endpoints after all security checks have passed.
    If the password is wrong, it:
        - updates all relevant defense mechanisem(rate limit, account lock, captcha)
        - writes adetailed log recordwith the given bad_password_reason
        - returns a fLASK JSON response with HTTP 401.
    If the password is correct, it returns None and the caller can continue the login flow.
    :param user: Dictionary with the user's data loaded from the users DB
    :param username: Username string, used for logging and for rate limit / lock tracking
    :param password: Text password provided in the current login request.
    :param bad_password_reason: String key describing the dalure reason for the logs
    :param start_time: Start time
    :return: If the password is incorrect ->(Flask Response, 401).
             If the password is correct -> None (caller continues the flow
    """
    if not verify_password(password, user):
        register_rate_limit_failure(username)
        register_account_failure(username)
        register_global_failure_for_captcha()
        log_attempt(username=username,
                    result=bad_password_reason,
                    hash_mode=HASH_MODE,
                    protection_flags=current_defenses(),
                    start_time=start_time)

        return jsonify({"error": "Incorrect password"}), 401
    return None


# ================================================
# ================ Flask app ====================
# ================================================
app = Flask(__name__)
# Load users from DB (user_db.json) without the _meta
raw_users = load_users()
users = {name: info for name, info in raw_users.items() if not name.startswith("_")}


@app.route("/")
def home():
    return "Server is running!"


# ================================================
# ================ Register route ===============
# ================================================
@app.route("/register", methods=["POST"])
def register():
    """
    New client registraion
    JSON input:
    {
        "username": "...",
        "password": "..."
    }
    Behavior:
      - Missin value:  error 400 + writes "missing_fields" to log
      - User already exists:  error 409
      else: Password hash and write to users_db.json
    """
    start_time = time.perf_counter()
    data = request.get_json() or {}

    username = data.get("username")
    password = data.get("password")
    # ===============================
    # ======= Input validation ======
    # ===============================

    error = check_required_fields(
        {"username": username, "password": password},
        missing_reason="missing_fields",
        error_message="Missing username or password",
        start_time=start_time
    )
    if error is not None:
        return error
    # =======================================
    # ======= Checking user existence =======
    # =======================================
    if username in users:
        log_attempt(
            username=username,
            result="register_user_exists",
            hash_mode=HASH_MODE,
            protection_flags=current_defenses(),
            start_time=start_time
        )
        return jsonify({"error": "User already exists"}), 409
    # =======================================
    # ============== Save user ==============
    # =======================================
    if HASH_MODE == "sha256_salt":
        salt = generate_salt()
    else:
        salt = ""
    pwd_hash = hash_password(password, salt, HASH_MODE)

    users[username] = {
        "password_hash": pwd_hash,
        "salt": salt,
        "strength": "manual",
        "hash_mode": HASH_MODE,
        "totp_enabled": False
    }
    # =======================================
    # ====== Save to DB users_db.json =======
    # =======================================
    save_users(users, GROUP_SEED)
    log_attempt(
        username=username,
        result="register_ok",
        hash_mode=HASH_MODE,
        protection_flags=current_defenses(),
        start_time=start_time
    )
    return jsonify({"status": "ok", "user": username})


# ================================================
# ================ Login route ==================
# ================================================
@app.route("/login", methods=["POST"])
def login():
    """
    Basic login
    Input: JSON:
    {
        "username":"...",
        "password":"..."
        "captch_token:"..." (optional. if required)
    }
    Actions:
    1. Validate required fields
    2. run_secuirty_login_checks()
    3. Password check
    4. If TOTP is active for the user returns error 401 "TOTP required"
    5. else: success("ok")
    """
    start_time = time.perf_counter()
    data = request.get_json() or {}

    username = data.get("username")
    password = data.get("password")

    # ===============================
    # ======= Input validation ======
    # ===============================
    error = check_required_fields({"username": username, "password": password},
                                  missing_reason="missing_fields",
                                  error_message="Missing username or password",
                                  start_time=start_time)
    if error is not None:
        return error
    # ================================================================
    # ================ Security_login_checks =========================
    # ================================================================
    user, error_response = run_security_login_checks(username, data, start_time)
    if error_response is not None:
        resp, status = error_response
        return resp, status
    # =====================================
    # ======= Password varification =======
    # =====================================
    error = check_password_and_log(
        user=user,
        username=username,
        password=password,
        bad_password_reason="bad_password",
        start_time=start_time
    )
    if error is not None:
        return error
    # =====================================
    # ============ Totp required? =========
    # =====================================
    if ENABLE_TOTP and user.get("totp_enabled"):
        log_attempt(
            username=username,
            result="totp_required",
            hash_mode=HASH_MODE,
            protection_flags=current_defenses(),
            start_time=start_time
        )
        return jsonify({"error": "TOTP required"}), 401
    # =====================================
    # ============== Success ==============
    # =====================================
    log_attempt(
        username=username,
        result="ok",
        hash_mode=HASH_MODE,
        protection_flags=current_defenses(),
        start_time=start_time
    )
    return jsonify({"status": "Logged in", "user": username}), 200


# ================================================
# ================ Login_totp route ==============
# ================================================
@app.route("/login_totp", methods=["POST"])
def login_totp():
    """
    Login when the user required TOTP
    Expected input: username, password, totp_code
        Input: JSON:
    {
        "username":"...",
        "password":"...",
        "totp_code":"...",
        "captch_token:"..." (optional. if required)
    }
    Action:
        1. Validating fields required
        2. Activate run_securtiy_login_checks()
        3. Validate TOTP active for this user
        4. Checking password
        5. Checking TOTP code
        6. If all good creates a log with ok_totp and returen success

    """
    start_time = time.perf_counter()
    data = request.get_json() or {}

    username = data.get("username")
    password = data.get("password")
    totp_code = data.get("totp_code")

    # ===============================
    # ======= Input validation ======
    # ===============================
    error = check_required_fields(
        {"username": username,
         "password": password,
         "totp_code": totp_code},
        missing_reason="missing_fields_totp",
        error_message="Missing username, password, or totp_code",
        start_time=start_time
    )
    if error is not None:
        return error
    # ================================================================
    # ================ Security_login_checks =========================
    # ================================================================
    user, error_response = run_security_login_checks(username, data, start_time)
    if error_response is not None:
        resp, status = error_response
        return resp, status
    # ====================================
    # ======= TOTP enabled  check  =======
    # ====================================
    if not (ENABLE_TOTP and user.get("totp_enabled")):
        return jsonify({"error": "TOTP not enabled for this user"}), 400

    # =====================================
    # ======= Password varification =======
    # =====================================
    error = check_password_and_log(
        user=user,
        username=username,
        password=password,
        bad_password_reason="bad_password_totp",
        start_time=start_time
    )
    if error is not None:
        return error
    # =====================================
    # ======= TOTP verification   =========
    # =====================================
    secret = user.get("totp_secret")
    if not secret or not verify_totp_code(secret, totp_code):
        register_rate_limit_failure(username)
        register_account_failure(username)
        register_global_failure_for_captcha()
        log_attempt(
            username=username,
            result="bad_totp_code",
            hash_mode=HASH_MODE,
            protection_flags=current_defenses(),
            start_time=start_time
        )
        return jsonify({"error": "Invalid TOTP code"}), 401

    # =====================================
    # ============== Success ==============
    # =====================================
    log_attempt(
        username=username,
        result="ok_totp",
        hash_mode=HASH_MODE,
        protection_flags=current_defenses(),
        start_time=start_time
    )
    return jsonify({"status": "Logged in with TOTP", "user": username}), 200
# ===================================================================
# ========================= Admin endpoint for CAPTCHA ==============
# ===================================================================
@app.route("/admin/get_captcha_token", methods=["POST"])
def get_captcha_token():
    """
    Admin endpoint to receive CAPTCHA token
    Input JSON:
    {
        "group_seed": REDACTED
    }
    Only if group_seed == GROUP_SEED, it will return
    a new token with an expiration date (expires_at) according to
    CAPTCHA_TOKEN_TLL_SECONDS.
    Create a senario which Admin can receive CAPTCHA token
    """
    data = request.get_json()
    seed = data.get("group_seed")
    if seed != GROUP_SEED:
        return jsonify({"error": "forbidden"}), 403
    token = uuid4().hex
    expires_at = datetime.now() + timedelta(seconds=CAPTCHA_TOKEN_TTL_SECONDS)
    captcha_tokens[token] = expires_at
    return jsonify(
        {
            "captcha_token": token,
            "expires_at": expires_at.isoformat(timespec="seconds"),
        }
    ), 200


if __name__ == "__main__":
    # Print to console the server configuration of defenses
    print(f"### SERVER STARTED, HASH_MODE = {HASH_MODE}, "
          f"RATE_LIMIT={'ON' if ENABLE_RATE_LIMIT else 'OFF'}, "
          f"ACCOUNT_LOCK={'ON' if ENABLE_ACCOUNT_LOCK else 'OFF'}, "
          f"CAPTCHA={'ON' if ENABLE_CAPTCHA else 'OFF'}, "
          f"TOTP={'ON' if ENABLE_TOTP else 'OFF'}, "
          f"PEPPER={'ON' if PEPPER else 'OFF'}, "
          f"LOG_FILE={LOG_FILE}"
          )
    app.run(port=5000)
