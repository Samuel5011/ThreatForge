from threatforge.alerting.alert_engine import create_alerts
from threatforge.detector.brute_force import detect_brute_force
from threatforge.parser.log_reader import read_auth_log


def main():
    events = read_auth_log("sample_logs/auth.log")

    detections = detect_brute_force(events)

    alerts = create_alerts(detections)

    if alerts:
        print("Alerts:")

        for alert in alerts:
            print(
                f" - {alert.source_ip}: "
                f"{alert.failed_attempts} failed attempts "
                f"({alert.severity})"
            )
    else:
        print("No alerts detected.")


if __name__ == "__main__":
    main()