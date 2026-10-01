import sys
import json
import argparse
from datetime import datetime, timezone
from soc_analyzer.rules import find_failure_window

failures = {}
parser = argparse.ArgumentParser(description="Анализатор SSH-журнала")
parser.add_argument("--threshold", type=int, default=5)
parser.add_argument("--window", type=int, default=300)
parser.add_argument("--file", default="samples/ssh_sample.jsonl")
args = parser.parse_args()

if args.threshold < 1:
    parser.error("--threshold должен быть не меньше 1")
if args.window <= 0:
    parser.error("--window должен быть больше 0")

threshold = args.threshold
window_seconds = args.window

try:
    log_file = open(args.file, encoding="utf-8")
except OSError as error:
    parser.error(f"Не удалось открыть файл {args.file}: {error.strerror}")

with  log_file as file:
    for line_number, line in enumerate(file, start=1):
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            print(
                f"Строка {line_number}: некорректный JSON, пропущена",
                file=sys.stderr,
            )
            continue

        if not isinstance(record, dict):
            print(
                f"Строка {line_number}: ожидался JSON-обьект, пропущена",
                file=sys.stderr
            )
            continue

        message = record.get("MESSAGE", "")

        if message.startswith(("Accepted password for ", "Accepted publickey for ", "Failed password for ")):
            timestamp = record.get("__REALTIME_TIMESTAMP")
            seconds = int(timestamp) / 1_000_000
            moment = datetime.fromtimestamp(seconds, tz=timezone.utc)

            if message.startswith("Accepted "):
                event_type = "login_success"
            else:
                event_type = "login_failure"
            parts = message.split()
            if parts[3:5] == ["invalid", "user"]:
                username = parts[5]
                source_ip = parts[7]
            else:
                username = parts[3]
                source_ip = parts[5]

            event = {
                "timestamp": moment,
                "event_type": event_type,
                "username": username,
                "source_ip": source_ip,
            }
            if event["event_type"] == "login_failure":
                key = (event["source_ip"], event["username"])
                if key not in failures:
                    failures[key] = []
                failures[key].append(event["timestamp"])

    for key, attempts in failures.items():
        print("IP и пользователь:", key, "Неудач:", len(attempts))

        window = find_failure_window(attempts, threshold, window_seconds)

        if window is not None:
            first_seen, last_seen = window

            print("SOC001: Возможный brute force", key)
            print("Начало", first_seen.isoformat())
            print("Конец", last_seen.isoformat())
