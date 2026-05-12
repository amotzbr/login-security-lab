from datetime import datetime
import glob
import json
import os
import csv

LOG_PATTERN = "Logs/**/attempts_*.log"

# תוצאות שנחשבות לוגין מוצלח
SUCCESS_RESULTS = {"ok", "ok_totp"}

TIME_FMT = "%Y-%m-%dT%H:%M:%S"

# === כאן אתה מתאים את המספרים למציאות שלך ===
# עבור brute-force (10k-most-common, MAX_ATTEMPTS=50000 לדוגמה)
BRUTE_FORCE_KEYSPACE = 50000

# עבור password spraying: מספר משתמשים * מספר סיסמאות נפוצות
# (לדוגמה: 30 משתמשים * 64 סיסמאות נפוצות = 1920)
PASSWORD_SPRAYING_KEYSPACE = 1920


def detect_attack_type(path: str) -> str:
    parts = path.split(os.sep)
    if "brute_force" in parts:
        return "brute_force"
    if "password_sparying" in parts or "password_spraying" in parts:
        return "password_spraying"
    return "unknown"


def detect_category(username: str) -> str:
    if username.startswith("weak_"):
        return "weak"
    if username.startswith("medium_"):
        return "medium"
    if username.startswith("strong_"):
        return "strong"
    return "mixed/unknown"


def get_keyspace(attack_type: str, total_attempts: int) -> int:
    """
    מנסה להחזיר keyspace תאורטי לפי סוג התקפה.
    אם לא ברור – נשתמש לפחות ב-total_attempts בפועל.
    """
    if attack_type == "brute_force":
        return BRUTE_FORCE_KEYSPACE
    if attack_type == "password_spraying":
        return PASSWORD_SPRAYING_KEYSPACE
    # fallback – נניח שמרחב החיפוש הוא מה שבאמת ניסינו
    return total_attempts


def analyze_single_log(path: str) -> dict | None:
    with open(path, "r") as f:
        rows = [json.loads(line) for line in f if line.strip()]

    if not rows:
        return None

    timestamps = [datetime.strptime(r["timestamp"], TIME_FMT) for r in rows]
    t0 = min(timestamps)
    t1 = max(timestamps)
    total_time = (t1 - t0).total_seconds()
    if total_time <= 0:
        total_time = 1e-9

    total_attempts = len(rows)
    attempts_per_second = total_attempts / total_time

    latencies = [r.get("latency_ms") for r in rows if "latency_ms" in r]
    avg_latency_ms = sum(latencies) / len(latencies) if latencies else None

    # הצלחות
    success_indices = [
        i for i, r in enumerate(rows) if r.get("result") in SUCCESS_RESULTS
    ]
    success_count = len(success_indices)
    failed_attempts = total_attempts - success_count

    if success_count:
        first_idx = success_indices[0]
        first_success_time = timestamps[first_idx]
        time_to_first_success = (first_success_time - t0).total_seconds()
        attempts_to_first_success = first_idx + 1
    else:
        time_to_first_success = None
        attempts_to_first_success = None

    first = rows[0]
    username = first.get("username", "")
    category = detect_category(username)
    hash_mode = first.get("hash_mode", "unknown")
    protections = first.get("protection_flags", {})
    defences_on = [name for name, enabled in protections.items() if enabled]

    attack_type = detect_attack_type(path)

    # ----- extrapolation -----
    keyspace = get_keyspace(attack_type, total_attempts)
    if attempts_per_second > 0:
        est_full_seconds = keyspace / attempts_per_second
    else:
        est_full_seconds = 0.0

    estimated_full_keyspace_seconds = round(est_full_seconds, 2)
    estimated_full_keyspace_hours = round(est_full_seconds / 3600, 2)

    return {
        "file": path,
        "attack_type": attack_type,
        "hash_mode": hash_mode,
        "defences": "+".join(defences_on) if defences_on else "none",
        "username": username,
        "category": category,

        # סיכום ניסיונות
        "total_attempts": total_attempts,
        "success_count": success_count,
        "failed_attempts": failed_attempts,
        "success_rate": round(success_count / total_attempts, 4),
        "fail_rate": round(failed_attempts / total_attempts, 4),

        # זמן כולל וקצב התקפה
        "total_time_seconds": round(total_time, 2),
        "attempts_per_second": round(attempts_per_second, 2),

        # זמן/ניסיונות עד הצלחה ראשונה (אם הייתה)
        "time_to_first_success_seconds": (
            round(time_to_first_success, 2) if time_to_first_success is not None else ""
        ),
        "attempts_to_first_success": attempts_to_first_success or "",

        # latency ממוצע מהשרת
        "avg_latency_ms": round(avg_latency_ms, 2) if avg_latency_ms is not None else "",

        # זמן משוער לפיצוח *כל מרחב הסיסמאות* (לפי keyspace)
        "keyspace_size": keyspace,
        "estimated_full_keyspace_seconds": estimated_full_keyspace_seconds,
        "estimated_full_keyspace_hours": estimated_full_keyspace_hours,
    }


def main():
    log_files = sorted(glob.glob(LOG_PATTERN, recursive=True))
    print(f"[+] נמצאו {len(log_files)} קבצי לוג לניתוח")

    results = []
    for path in log_files:
        print(f"[*] מנתח {path} ...")
        row = analyze_single_log(path)
        if row:
            results.append(row)

    if not results:
        print("לא נמצאו תוצאות לכתיבה")
        return

    out_file = "log_summary.csv"
    fieldnames = [
        "file",
        "attack_type",
        "hash_mode",
        "defences",
        "username",
        "category",
        "total_attempts",
        "success_count",
        "failed_attempts",
        "success_rate",
        "fail_rate",
        "total_time_seconds",
        "attempts_per_second",
        "time_to_first_success_seconds",
        "attempts_to_first_success",
        "avg_latency_ms",
        "keyspace_size",
        "estimated_full_keyspace_seconds",
        "estimated_full_keyspace_hours",
    ]

    with open(out_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in results:
            writer.writerow(row)

    print(f"[+] סיכום נכתב לקובץ: {out_file}")


if __name__ == "__main__":
    main()