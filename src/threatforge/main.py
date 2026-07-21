from threatforge.detector.brute_force import detect_brute_force
from threatforge.parser.log_reader import read_auth_log


def main() :
    events = read_auth_log("sample_logs/auth.log")

    suspicious_ips = detect_brute_force(events)

    print("Suspicious IPs:")

    for ip in suspicious_ips:
        print(f"- {ip}")


if __name__ == "__main__":
    main()