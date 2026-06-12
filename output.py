import json
import sys
from colorama import Fore, Style, init

init(autoreset=True)

ALERTS_FILE = "alerts.json"

SEVERITY_COLORS = {
    "critical": Fore.RED + Style.BRIGHT,
    "high":     Fore.YELLOW + Style.BRIGHT,
    "medium":   Fore.CYAN,
    "low":      Fore.WHITE,
}

SEVERITY_LABEL = {
    "critical": "[ CRITICAL ]",
    "high":     "[   HIGH   ]",
    "medium":   "[  MEDIUM  ]",
    "low":      "[   LOW    ]",
}


def print_alert(alert):
    severity = alert.get("severity", "low")
    color = SEVERITY_COLORS.get(severity, Fore.WHITE)
    label = SEVERITY_LABEL.get(severity, "[  INFO   ]")

    timestamp = alert["timestamp"]
    src_ip    = alert["src_ip"]
    atype     = alert["alert_type"]
    detail    = alert["detail"]

    line = (
        f"{Fore.LIGHTBLACK_EX}{timestamp}{Style.RESET_ALL}  "
        f"{color}{label}{Style.RESET_ALL}  "
        f"{Fore.LIGHTBLUE_EX}{src_ip:<18}{Style.RESET_ALL}  "
        f"{Fore.LIGHTGREEN_EX}{atype:<22}{Style.RESET_ALL}  "
        f"{Fore.WHITE}{detail}{Style.RESET_ALL}"
    )

    print(line)


def log_alert(alert):
    with open(ALERTS_FILE, "a") as f:
        f.write(json.dumps(alert) + "\n")


def handle_alert(alert):
    print_alert(alert)
    log_alert(alert)
