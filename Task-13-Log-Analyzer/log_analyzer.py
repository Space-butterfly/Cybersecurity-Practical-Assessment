
import csv
import argparse
from datetime import datetime, timedelta
from collections import defaultdict, deque


# Detection configuration
FAILURE_THRESHOLD = 5
TIME_WINDOW_MINUTES = 10
SUCCESS_WARNING_THRESHOLD = 3


def load_logs(filename):
    """Read and validate authentication logs from a CSV file."""
    required_columns = {"timestamp", "username", "source_ip", "event"}
    logs = []

    with open(filename, "r", newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)

        if not reader.fieldnames or not required_columns.issubset(reader.fieldnames):
            raise ValueError("CSV is missing required columns.")

        for row_number, row in enumerate(reader, start=2):
            try:
                timestamp = datetime.fromisoformat(row["timestamp"])
                username = row["username"].strip()
                source_ip = row["source_ip"].strip()
                event = row["event"].strip().upper()

                if not username or not source_ip:
                    raise ValueError("Username or source IP is empty.")

                if event not in {"SUCCESS", "FAILURE"}:
                    raise ValueError("Event must be SUCCESS or FAILURE.")

                logs.append({
                    "timestamp": timestamp,
                    "username": username,
                    "source_ip": source_ip,
                    "event": event
                })

            except (ValueError, TypeError) as error:
                raise ValueError(
                    f"Invalid data on CSV row {row_number}: {error}"
                ) from error

    return sorted(logs, key=lambda item: item["timestamp"])


def analyze_logs(logs):
    """Detect repeated failures and successful logins after failures."""
    alerts = []
    failure_history = defaultdict(deque)
    alerted_keys = set()

    time_window = timedelta(minutes=TIME_WINDOW_MINUTES)

    for log in logs:
        key = (log["username"], log["source_ip"])
        timestamp = log["timestamp"]

        history = failure_history[key]

        # Remove failed attempts outside the rolling time window.
        while history and timestamp - history[0] > time_window:
            history.popleft()

        if log["event"] == "FAILURE":
            history.append(timestamp)

            if len(history) >= FAILURE_THRESHOLD and key not in alerted_keys:
                alerts.append({
                    "type": "REPEATED_FAILED_LOGINS",
                    "severity": "HIGH",
                    "username": log["username"],
                    "source_ip": log["source_ip"],
                    "time": timestamp,
                    "details": (
                        f"{len(history)} failed login attempts "
                        f"within {TIME_WINDOW_MINUTES} minutes."
                    )
                })
                alerted_keys.add(key)

        elif log["event"] == "SUCCESS":
            if len(history) >= SUCCESS_WARNING_THRESHOLD:
                alerts.append({
                    "type": "SUCCESS_AFTER_REPEATED_FAILURES",
                    "severity": "MEDIUM",
                    "username": log["username"],
                    "source_ip": log["source_ip"],
                    "time": timestamp,
                    "details": (
                        f"Successful login after {len(history)} "
                        "recent failed attempts."
                    )
                })

            # Reset the failure sequence after a successful login.
            history.clear()
            alerted_keys.discard(key)

    return alerts


def print_report(alerts):
    """Display the security analysis report."""
    print("\n========== AUTHENTICATION LOG ANALYSIS ==========")
    print(f"Total alerts detected: {len(alerts)}")

    if not alerts:
        print("No suspicious authentication patterns detected.")

    for number, alert in enumerate(alerts, start=1):
        print(f"\nAlert #{number}")
        print(f"Type: {alert['type']}")
        print(f"Severity: {alert['severity']}")
        print(f"Username: {alert['username']}")
        print(f"Source IP: {alert['source_ip']}")
        print(f"Time: {alert['time']}")
        print(f"Details: {alert['details']}")

    print("\n==================================================")


def main():
    parser = argparse.ArgumentParser(
        description="Analyze authentication logs for suspicious activity."
    )
    parser.add_argument(
        "file",
        help="Path to the authentication CSV log file."
    )
    parser.add_argument(
        "-o", "--output",
        help="Optional file to save the analysis report."
    )

    args = parser.parse_args()

    try:
        logs = load_logs(args.file)
        alerts = analyze_logs(logs)
        print_report(alerts)

        if args.output:
            with open(args.output, "w", encoding="utf-8") as file:
                file.write(
                    f"Authentication Log Analysis\n"
                    f"Total alerts detected: {len(alerts)}\n\n"
                )
                for alert in alerts:
                    file.write(
                        f"{alert['severity']} - {alert['type']}\n"
                        f"Username: {alert['username']}\n"
                        f"Source IP: {alert['source_ip']}\n"
                        f"Time: {alert['time']}\n"
                        f"Details: {alert['details']}\n\n"
                    )

            print(f"\nReport saved to: {args.output}")

    except (OSError, ValueError) as error:
        print(f"Error: {error}")


if __name__ == "__main__":
    main()
