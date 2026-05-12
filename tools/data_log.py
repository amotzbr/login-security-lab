from datetime import datetime
import re

def main():
    log_file = "attempts_baseline_bcrypt.log"

    timestamps = []

    with open(log_file, "r") as f:
        for line in f:
            m = re.search(r'"timestamp":\s*"([^"]+)"', line)
            if m:
                timestamps.append(m.group(1))

    if not timestamps:
        print("לא נמצאו timestamps בקובץ")
        return

    fmt = "%Y-%m-%dT%H:%M:%S"
    t0 = datetime.strptime(timestamps[0], fmt)
    t1 = datetime.strptime(timestamps[-1], fmt)

    total_seconds = (t1 - t0).total_seconds()
    print(f"Attempts: {len(timestamps)}")
    print(f"Total time: {total_seconds:.2f} seconds")
    print(f"Average rate: {len(timestamps)/total_seconds:.2f} attempts/sec")

if __name__ == "__main__":
    main()