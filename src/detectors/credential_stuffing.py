from collections import defaultdict
from detectors.base_detectors import BaseDetector

class CredentialStuffingDetector(BaseDetector):

    def __init__(self, threshold=5):

        super().__init__(threshold)

        self.activity = defaultdict(
            lambda: {
                "failed_users": set(),
                "failed_count": 0,
                "successful_login": False
            }
        )
    def analyze(self, event):
        
        if event is None:
            return None

        ip = event["ip"]
        activity = self.activity[ip]

        if event["action"] == "Login failed":
            activity["failed_users"].add(event["user"])
            activity["failed_count"] += 1
        elif event["action"] == "Login successful":
            activity["successful_login"] = True

        if len(activity["failed_users"]) >= self.threshold and activity["successful_login"]:
            if ip in self.alerted:
                return None

            self.alerted.add(ip)

            return self.create_alert(
                attack="Credential Stuffing",
                severity="Critical",
                timestamp=event["timestamp"],
                source_ip=ip,
                details=(
                    f"{len(activity['failed_users'])} users targeted, "
                    f"{activity['failed_count']} failed logins "
                    f"followed by a successful authentication."
                ),
                recommendation=(
                    "Investigate possible reuse of leaked credentials. "
                    "Reset affected accounts and enable MFA."
                ),
            )

        return None