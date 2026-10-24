# Python Security Log Analyzer

A lightweight Python tool for analyzing authentication logs, detecting repeated failed login attempts, and generating structured security reports.

The project demonstrates log parsing, input validation, time-window-based detection, automated testing, and continuous integration using GitHub Actions.

## Features

- **CSV log parsing** — Reads authentication events from CSV files.
- **Input validation** — Validates timestamps, IP addresses, event types, and required fields.
- **Event statistics** — Counts successful and failed authentication events, malformed rows, and unique IP addresses.
- **AUTH-001: Repeated failures** — Detects repeated failed authentication attempts from the same source IP within a configurable sliding time window.
- **AUTH-002: Multiple source IPs** — Detects a username receiving failed authentication attempts from multiple distinct source IP addresses within the configured time window.
- **AUTH-003: Multiple targeted usernames** — Detects a source IP generating failed authentication attempts against multiple distinct usernames within the configured time window.
- **Structured alerts** — Includes rule identifiers, descriptions, thresholds, and relevant timestamps in detection results.
- **JSON reporting** — Prints a machine-readable report and saves it to `reports/report.json`.
- **Automated testing** — Includes unit tests for detection rules, malformed input, timestamp normalization, time-window behavior, and edge cases.
- **Continuous integration** — Uses GitHub Actions to run tests and execute the sample analysis.

## Requirements

- Python 3.10 or newer
- No third-party dependencies

## Getting Started

Clone the repository and navigate to the project directory:

```bash
git clone https://github.com/tommmy99/Python-Security-Log-Analyzer.git
cd Python-Security-Log-Analyzer
```

Run the analyzer against the included sample logs:

```bash
python log_analyzer.py sample_logs.csv
```

Customize the detection threshold and time window:

```bash
python log_analyzer.py sample_logs.csv --threshold 3 --window-minutes 10
```

Run the automated tests:

```bash
python -m unittest -v
```

## Input Format

The input file must be a CSV containing the following columns:

| Column | Description |
|---|---|
| `timestamp` | ISO 8601 date and time of the event |
| `ip` | Source IP address |
| `username` | Username associated with the authentication attempt |
| `event` | Authentication event type: `FAILED` or `SUCCESS` |

Example:

```csv
timestamp,ip,username,event
2026-10-24T09:00:00,192.0.2.10,alice,FAILED
2026-10-24T09:01:00,192.0.2.10,bob,FAILED
2026-10-24T09:02:00,192.0.2.10,alice,SUCCESS
```

The included sample data uses documentation IP addresses and is synthetic.
## Detection Logic

The analyzer processes authentication events in chronological order and evaluates failed attempts using configurable sliding time windows. Successful authentication events are counted but excluded from the three failure-based detection rules.

The default threshold is five and the default detection window is ten minutes.

The analyzer implements the following rules:

- **AUTH-001 — Repeated failures from one IP:** Detects a source IP generating at least the configured number of failed authentication attempts within the time window.
- **AUTH-002 — Multiple source IPs targeting one username:** Detects a username receiving failed authentication attempts from at least the configured number of distinct source IP addresses within the time window.
- **AUTH-003 — One IP targeting multiple usernames:** Detects a source IP generating failed authentication attempts against at least the configured number of distinct usernames within the time window.

Alerts include the applicable rule identifier, a description, the configured threshold and window duration, and relevant timestamps or counts.

For AUTH-001, alerts also include the total number of observed failures, the maximum number of failures within a detection window, and the first and last observed failure timestamps.

The `--threshold` and `--window-minutes` command-line options allow the detection settings to be customized.

These rules identify patterns that may warrant investigation; they do not establish that an attack has occurred.

## Output

The analyzer prints a JSON report to the terminal and saves it to `reports/report.json`.
The report contains the following sections:

- **`summary`** — Counts of valid events, successful and failed events, malformed rows, and unique IP addresses.
- **`suspicious_ips`** — AUTH-001 alerts for repeated failed attempts from individual source IP addresses.
- **`suspicious_usernames`** — AUTH-002 alerts for usernames targeted by multiple distinct source IP addresses.
- **`suspicious_ip_targets`** — AUTH-003 alerts for source IP addresses targeting multiple distinct usernames.
- **`configuration`** — The threshold and time window used during analysis.

## Testing and Continuous Integration

The project includes unit tests covering:

- Repeated failures and configurable thresholds
- Failures inside and outside the time window
- Boundary conditions
- Timestamp normalization across time zones
- Invalid IP addresses, timestamps, event types, and incomplete rows
- Missing files and required CSV columns
- Alert metadata and deterministic ordering

GitHub Actions runs the test suite and executes the sample analysis on pushes to the configured branches and on pull requests targeting `main`.

## Limitations

This tool identifies patterns that may warrant further investigation. An alert does not prove that an attack occurred or identify the person responsible.

The current implementation:

- Does not correlate authentication attempts across multiple source IP addresses to identify broader distributed attack campaigns beyond the implemented detection rules.
- Does not correlate events across different systems.
- Does not establish whether an IP address belongs to a legitimate user, a proxy, or an attacker.
- Does not replace a SIEM, an intrusion detection system, or a full incident-response process.

The included logs are synthetic and intended for educational and testing purposes.

## Security and Privacy

Only analyze logs you are authorized to access. Authentication logs may contain personal data or other sensitive information. Review both input files and generated reports before sharing them.

## Future Improvements

Potential extensions include:

- Detection of distributed login attacks across multiple IP addresses
- Configurable detection rules
- Additional input formats and log sources
- More detailed test coverage and edge-case handling
- Improved report summaries for security investigations
