"""
generate_users.py

Utility script to create 30 demo users for the login system:
    - 10 weak passwords
    - 10 medium passwords
    - 10 strong passwords

For each user it creates:
- Entry in seed_users (users.json) with a clear text password and strength.
- Entry in db_users (users_db.json) with hash, salt, hash_mode and TOTP flags.

TOTP is enabled only for a fixed subset of users.
"""
from auth_security import hash_password, generate_salt, save_users
from config import HASH_MODE, GROUP_SEED, USERS_SEED_FILE, ENABLE_TOTP, TOTP_USERS_COUNT
import json
from auth_security import generate_totp_secret

weak_passwords = [
    "home","dooney", "1111", "0000", "abcd",
    "2508", "REDACTED", "5555", "password", "4321"
]
medium_passwords = [
    "amotz123","noam1509", "a3yd5hs3", "e3n5u7m9", "maccabi3008",
    "gal2008baruch", "israel1987", "silver400", "identity2232", "sdsmd2323"
]
strong_passwords = [
    "AmoTz@Br%!!","NoAm@$%4b5r", "MaCa!@)bi{ha{i", "H*ck('me_ifU_can_",
    "StRoNg*&*&pAssword&%$","G00D&^LUck", "1)GG$$%^YYUh" ,
    "D))ooney&&barUch", "N0%#@mercy563!", "Str0Ng__@)paSs"
]
TOTP_USERS = {
    "weak_user_9",
    "medium_user_3",
    "medium_user_7",
    "strong_user_2",
    "strong_user_8",
}
# TOTP currently assigned to users
totp_assigned = 0
# Create new users
def add_users(group, passwords: list[str], seed_users: dict, db_users: dict):
    """
    Create users for a given strength group and populate both:
     - seed_users
     - db_users
     
    :param group: Strength label ("weak" / "medium"/ "strong").
    :param passwords: List of plain text passwords for this group.
    :param seed_users: Dict that will be written later to USERS_SEED_FILE.
    :param db_users: Dict that will be written later to users_db.json.
    :return:
    """
    global totp_assigned
    for i, pwd in enumerate(passwords, start=1):
        username = f"{group}_user_{i}"
        # Seed (users.json)
        seed_users[username]={
            "password": pwd,
            "strength": group
        }
        # DB (users_db.json)
        if HASH_MODE == "sha256_salt":
            salt = generate_salt()
        else:
            salt=""
        pwd_hash = hash_password(pwd, salt,HASH_MODE)
        db_users[username] = {
            "password_hash": pwd_hash,
            "salt": salt,
            "strength": group,
            "hash_mode": HASH_MODE,
            "totp_enabled": False
        }
        if ENABLE_TOTP and username in TOTP_USERS and totp_assigned < TOTP_USERS_COUNT:
            secret = generate_totp_secret()
            seed_users[username]["totp_secret"] = secret
            db_users[username]["totp_secret"] = secret
            db_users[username]["totp_enabled"] =True
            totp_assigned += 1


def main():
    """
    Build the full users set
    """
    seed_users: dict[str, dict] = {}
    db_users: dict[str,dict] = {}

    add_users("weak", weak_passwords, seed_users, db_users)
    add_users("medium", medium_passwords, seed_users, db_users)
    add_users("strong", strong_passwords, seed_users, db_users)
    seed_to_save = dict(seed_users)
    seed_to_save["_meta"] = {"group_seed":GROUP_SEED}
    with open(USERS_SEED_FILE, "w") as f:
        json.dump(seed_to_save, f, indent=4)

    save_users(db_users, GROUP_SEED)
    print("30 users generated:")
    print(f"- seed file:{USERS_SEED_FILE}")
    print("- DB file: users_db.json")


if __name__ == "__main__":
    main()

