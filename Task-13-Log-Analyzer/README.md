
# Authentication Log Analyzer

## 1. Project Overview

A Python-based defensive security tool that analyzes authentication logs in CSV format and identifies suspicious login patterns.

The tool uses synthetic authentication data and Python's standard library. No external packages are required.

## 2. Objectives

- Identify repeated failed login attempts.
- Detect successful logins following repeated failures.
- Associate events with usernames and source IP addresses.
- Generate a readable security alert report.
- Validate input data and reject invalid events.

## 3. Detection Rules

| Rule | Condition | Severity |
|---|---|---|
| Repeated failed logins | 5 or more failures for the same username and source IP within 10 minutes | HIGH |
| Successful login after repeated failures | A successful login follows at least 3 recent failures for the same username and source IP | MEDIUM |

## 4. Project Structure

```text
Task-13-Log-Analyzer/
├── log_analyzer.py
├── sample_logs.csv
├── test_logs_analyzer.py
├── analysis_report.txt
└── README.md
```

## 5. Requirements

- Python 3.10 or later
- No third-party dependencies

## 6. How to Run

From the project root:

```powershell
python .\Task-13-Log-Analyzer\log_analyzer.py .\Task-13-Log-Analyzer\sample_logs.csv
```

To save a report:

```powershell
python .\Task-13-Log-Analyzer\log_analyzer.py .\Task-13-Log-Analyzer\sample_logs.csv --output .\Task-13-Log-Analyzer\analysis_report.txt
```

## 7. Run Automated Tests

```powershell
python -m unittest -v .\Task-13-Log-Analyzer\test_logs_analyzer.py
```

## 8. Test Results

All 5 automated tests passed:

1. Five failed logins trigger an alert.
2. Successful login after repeated failures is detected.
3. Failures outside the configured time window do not accumulate.
4. Different usernames are analyzed separately.
5. Invalid event values are rejected.

## 9. Limitations

- The tool analyzes authentication logs; it does not monitor a live system.
- Repeated failures may be caused by legitimate user mistakes.
- Users behind shared VPNs or NAT gateways may share a source IP.
- Distributed attacks across multiple IP addresses may not be detected by the current grouping rule.
- The alerts are indicators of suspicious activity, not proof of account compromise.
- The detection thresholds are configurable but are currently fixed in the source code.

## 10. Security and Privacy

The project uses synthetic data and does not collect passwords, API keys, or real user credentials.

## 11. Future Improvements

- Detect distributed brute-force attempts.
- Add configurable detection thresholds.
- Export reports in JSON format.
- Add severity-based filtering.
- Integrate with real authentication log sources.
