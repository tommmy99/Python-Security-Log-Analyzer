# Python Security Log Analyzer

A lightweight Python tool for analyzing authentication logs and identifying potentially suspicious login activity.

## Features

- Parses CSV authentication logs.
- Validates timestamps, IP addresses, and event types.
- Counts successful and failed authentication events.
- Detects repeated failed login attempts within a configurable time window.
- Generates a structured JSON report.
- Handles malformed log entries and missing files.
- Includes automated unit tests.

## Requirements

- Python 3.10 or newer
- No third-party dependencies

## Usage

Run the analyzer:

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

## Detection Logic

The tool groups failed authentication events by IP address and analyzes them using a sliding time window.

An alert is generated when the number of failed attempts within the configured time window reaches the specified threshold.

## Output

The tool generates a JSON report containing:

- Total valid events
- Successful and failed authentication counts
- Number of malformed rows
- Number of unique IP addresses
- Potentially suspicious IP addresses
- Detection configuration

## Limitations

This tool identifies patterns that may warrant investigation. An alert does not prove that an attack occurred or identify the person responsible.

The current implementation does not detect distributed attacks involving multiple IP addresses or correlate events across different systems.

The included logs are synthetic and intended for educational purposes.

## Security and Privacy

Only analyze logs you are authorized to access. Review log files and reports for sensitive information before sharing them publicly.

## Future Improvements

- Support additional authentication log formats.
- Add more detection rules.
- Include severity levels and remediation recommendations.
- Generate human-readable HTML reports.
- Automate testing with GitHub Actions.
