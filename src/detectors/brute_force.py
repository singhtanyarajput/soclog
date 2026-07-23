from collections import defaultdict
from datetime import datetime, timedelta
from detectors.base_detectors import BaseDetector
class BruteForceDetector(BaseDetector):

    def __init__(self, threshold=5):

        super().__init__(threshold)

        self.failed_attempts = defaultdict(list)
        
    def analyze(self, event):

        if event is None:
            return None

        if event["action"] != "Login failed":
            return None

        key = (
            event["ip"],
            event["user"]
        )
        current_time = datetime.strptime(event["timestamp"], "%Y-%m-%d %H:%M:%S")

        self.failed_attempts[key].append(current_time)
        window = timedelta(seconds=60)
        self.failed_attempts[key] = [t for t in self.failed_attempts[key] if current_time - t <= window]

        count = len(self.failed_attempts[key])

        if key in self.alerted:
            return None

        if count >= self.threshold:
            self.alerted.add(key)
            return self.create_alert(
                attack="Brute Force",
                severity="High",
                timestamp=event["timestamp"],
                source_ip=event["ip"],
                details=(f"{count} failed logins attempts" f"for user '{event['user']}'" f"from IP {event['ip']} within 1 minute."),
                recommendation="Investigate repeated failed authentication attempts.",
            )

        return None