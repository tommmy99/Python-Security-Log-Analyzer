import argparse
import csv
import ipaddress
import json

from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path


#! Parse an ISO 8601 timestamp and normalize it to UTC
def parse_timestamp(value):
    timestamp = datetime.fromisoformat(value.strip())

    #* Treat timestamps without timezone information as UTC
    #* This ensures that all timestamps can be compared consistently

    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)

    #* Convert timezone-aware timestamps to UTC for consistent processing
    return timestamp.astimezone(timezone.utc)

#! Analyze authentication logs and detect repeated failures
def analyze_log(path, threshold=5, window_minutes=10):

    #* Reject invalid detection settings before processing the input file
    if threshold < 1 or window_minutes < 1:
        raise ValueError("Threshold and window must be positive.")

    path = Path(path)

    #*Ensure that the input path points to an existing file
    if not path.is_file():
        raise FileNotFoundError(f"Log file not found: {path}")

    events = []
    malformed_rows = 0

    #* Read the CSV using DictReader so each field can be accessed by name
    with path.open("r", encoding="utf-8", newline="") as file:
        reader = csv.DictReader(file)

        #* Verify that the input contains all fields required for analysis
        required_columns = {"timestamp", "ip", "username", "event"}

        if (
            not reader.fieldnames
            or not required_columns.issubset(reader.fieldnames)
        ):
            raise ValueError(
                "CSV must contain timestamp, ip, username, event columns."
            )

        #* Validate each row and retain only well-formed authentication events
        for row in reader:
            try:

                #* Parse the timestamp and normalize it to UTC.
                timestamp = parse_timestamp(row["timestamp"])

                #* Validate the IP address and store its canonical representation
                ip = str(
                    ipaddress.ip_address(row["ip"].strip())
                )

                #* Read and normalize the username
                username = row["username"].strip()

                if not username:
                    raise ValueError("Missing username")

                #* Normalize the event type to avoid case-sensitive mismatches
                event_type = row["event"].strip().upper()

                #* Only the supported authentication outcomes are accepted
                if event_type not in {"FAILED", "SUCCESS"}:
                    raise ValueError("Unknown event type")

                #* Store validated events in a consistent internal format
                events.append({
                    "timestamp": timestamp,
                    "ip": ip,
                    "username": username,
                    "event": event_type,
                })

            #* Count malformed rows instead of stopping the entire analysis
            except (ValueError, AttributeError, TypeError):
                malformed_rows += 1

    #* Process events chronologically so the sliding-window detection is correct
    events.sort(key=lambda event: event["timestamp"])

    #* Track overall event counts and per-IP authentication statistics
    event_counts = Counter()
    failures_by_ip = Counter()
    successful_by_ip = Counter()

    #* Store recent failed-attempt timestamps separately for each IP address
    #* A deque allows old timestamps to be removed efficiently from the front
    windows = defaultdict(deque)

    #* Track recent failed attempts for each username and source IP
    failures_by_username = defaultdict(deque)

    #* Track recent distinct usernames targeted by each source IP
    usernames_by_ip = defaultdict(deque)

    #* Dictionaries that will store the time boundaries for the failures and the detection window.
    first_failure_by_ip = {}
    last_failure_by_ip = {}
    detection_window_by_ip = {}

    #* Record the highest number of failures observed in any window for each IP
    max_failures_in_window = Counter()

    #* Track the maximum number of distinct source IPs per username
    max_ips_per_username = Counter()
    detection_window_by_username = {}

    #* Track the maximum number of distinct usernames per source IP
    max_usernames_per_ip = Counter()
    detection_window_by_ip_usernames = {}

    window = timedelta(minutes=window_minutes)


    #* Analyze validated events in chronological order
    for event in events:
        ip = event["ip"]
        username = event["username"]
        timestamp = event["timestamp"]

        #* Count successful and failed events across the entire input
        event_counts[event["event"]] += 1

        #* Successful logins contribute to statistics but not to failure alerts
        if event["event"] == "SUCCESS":
            successful_by_ip[ip] += 1
            continue

        #* Count all failed attempts for this IP, regardless of their time
        failures_by_ip[ip] += 1

        #* Track failed attempts for each username and source IP
        failures_by_username[username].append((timestamp, ip))

        #* Retrieve recent failed attempts for the current username
        username_attempts = failures_by_username[username]

        #* Remove attempts outside the configured time window
        while (
            username_attempts
            and timestamp - username_attempts[0][0] > window
        ):
            username_attempts.popleft()

        #* Count distinct source IPs targeting this username
        distinct_ips = {
            attempt_ip
            for _, attempt_ip in username_attempts
        }

        #* Update the maximum number of distinct IPs observed
        if len(distinct_ips) > max_ips_per_username[username]:
            max_ips_per_username[username] = len(distinct_ips)
            detection_window_by_username[username] = {
                "start": username_attempts[0][0],
                "end": timestamp,
            }

        #* Track failed attempts for each source IP and targeted username
        usernames_by_ip[ip].append((timestamp, username))


        #* Retrieve recent failed attempts for the current source IP
        ip_attempts = usernames_by_ip[ip]

        #* Remove attempts outside the configured time window
        while (
            ip_attempts
            and timestamp - ip_attempts[0][0] > window
        ):
            ip_attempts.popleft()

        #* Count distinct usernames targeted by this source IP
        distinct_usernames = {
            attempt_username
            for _, attempt_username in ip_attempts
        }

        #* Update the maximum number of distinct usernames observed
        if len(distinct_usernames) > max_usernames_per_ip[ip]:
            max_usernames_per_ip[ip] = len(distinct_usernames)
            detection_window_by_ip_usernames[ip] = {
                "start": ip_attempts[0][0],
                "end": timestamp,
            }

        #* Record the first and most recent failed attempt for each IP
        if ip not in first_failure_by_ip:
            first_failure_by_ip[ip] = timestamp

        last_failure_by_ip[ip] = timestamp

        #* Retrieve the queue of recent failed attempts for the current IP
        recent = windows[ip]

        #* Remove attempts that fall outside the configured time window
        while recent and timestamp - recent[0] > window:
            recent.popleft()

        #* Include the current failed attempt in the active window
        recent.append(timestamp)

        current_count = len(recent)

        if current_count > max_failures_in_window[ip]:
            max_failures_in_window[ip] = current_count
            detection_window_by_ip[ip] = {
                "start": recent[0],
                "end": timestamp,
            }


    suspicious_usernames = []

    #* Flag usernames targeted by enough distinct source IPs
    for username, count in max_ips_per_username.items():
        if count >= threshold:
            window_details = detection_window_by_username[username]

            suspicious_usernames.append({
                "username": username,
                "distinct_source_ips": count,
                "detection_window_start": (
                    window_details["start"].isoformat()
                ),
                "detection_window_end": (
                    window_details["end"].isoformat()
                ),
                "rule_id": "AUTH-002",
                "rule_description": (
                    "The same username received failed authentication "
                    "attempts from multiple source IPs within the "
                    "configured time window."
                ),
                "threshold": threshold,
                "window_minutes": window_minutes,
            })

    suspicious_ip_targets = []

    #* Flag source IPs targeting enough distinct usernames
    for ip, count in max_usernames_per_ip.items():
        if count >= threshold:
            window_details = detection_window_by_ip_usernames[ip]

            suspicious_ip_targets.append({
                "ip": ip,
                "distinct_usernames": count,
                "detection_window_start": (
                    window_details["start"].isoformat()
                ),
                "detection_window_end": (
                    window_details["end"].isoformat()
                ),
                "rule_id": "AUTH-003",
                "rule_description": (
                    "The same source IP generated failed authentication "
                    "attempts against multiple usernames within the "
                    "configured time window."
                ),
                "threshold": threshold,
                "window_minutes": window_minutes,
            })

    suspicious_ips = []

    #* Flag IP addresses whose maximum failure count reaches the threshold
    for ip, count in max_failures_in_window.items():
        if count >= threshold:

            window_details = detection_window_by_ip[ip]

            suspicious_ips.append({
                "ip": ip,
                "failed_attempts": failures_by_ip[ip],
                "max_failures_in_window": count,
                "first_failure": first_failure_by_ip[ip].isoformat(),
                "last_failure": last_failure_by_ip[ip].isoformat(),
                "detection_window_start": window_details["start"].isoformat(),
                "detection_window_end": window_details["end"].isoformat(),
                "rule_id": "AUTH-001",
                "rule_description": (
                    "Repeated failed authentication attempts from one IP "
                    "within the configured time window."
                ),
                "threshold": threshold,
                "window_minutes": window_minutes,
            })

    #* Show the IP addresses with the highest observed failure counts first
    suspicious_ips.sort(
        key=lambda item: (
            -item["max_failures_in_window"],
            item["ip"],
        )
    )

    #* Return a structured report that can be printed or serialized as JSON
    return {
        "summary": {
            "total_valid_events": len(events),
            "failed_events": event_counts["FAILED"],
            "successful_events": event_counts["SUCCESS"],
            "malformed_rows": malformed_rows,

            #* Count distinct IP addresses among validated events
            "unique_ips": len({
                event["ip"] for event in events
            }),
        },
        "suspicious_ips": suspicious_ips,
        "suspicious_usernames": suspicious_usernames,
        "suspicious_ip_targets": suspicious_ip_targets,
        "configuration": {
            "threshold": threshold,
            "window_minutes": window_minutes,
        },
    }

#! Parse command-line arguments, run the analysis, and save the report
def main():

    #* Define the command-line interface and its usage description
    parser = argparse.ArgumentParser(
        description=(
            "Analyze authentication logs for suspicious patterns"
        )
    )

    #* Positional argument specifying the CSV file to analyze.
    parser.add_argument(
        "logfile",
        help="Path to the input CSV file",
    )

    #* Optional threshold: the number of failures needed to trigger an alert
    parser.add_argument(
        "--threshold",
        type=int,
        default=5,
        help="Failed attempts required to trigger an alert",
    )

    #* Optional duration of the sliding window used by the detection logic
    parser.add_argument(
        "--window-minutes",
        type=int,
        default=10,
        help="Time window in minutes",
    )

    #* Optional destination for the generated JSON report
    parser.add_argument(
        "--output",
        default="reports/report.json",
        help="Output JSON report path",
    )

    args = parser.parse_args()

    try:

        #* Analyze the input using the selected detection parameters
        report = analyze_log(
            args.logfile,
            args.threshold,
            args.window_minutes,
        )

        output_path = Path(args.output)

        #* Create the output directory if it does not already exist
        output_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        #* Serialize the report as readable JSON and write it to disk
        output_path.write_text(
            json.dumps(report, indent=2),
            encoding="utf-8",
        )

        #* Print the same report to the terminal for immediate inspection
        print(json.dumps(report, indent=2))
        print(f"\nReport saved to: {output_path}")

    #* Convert common file, input-validation, and CSV errors into CLI messages
    except (OSError, ValueError, csv.Error) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
