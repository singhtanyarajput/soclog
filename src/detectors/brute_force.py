from collections import defaultdict
from datetime import datetime, timedelta

class BruteForceDetector:

    def __init__(self, threshold=5):

        self.threshold = threshold

        self.failed_attempts = defaultdict(list)
        self.alerted = set()
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
        self.failed_attempts[key] = [t for t in self.failed_attempts[key] if current_time - t < window]

        count = len(self.failed_attempts[key])  
        if key in self.alerted:
            return None
        if count >= self.threshold:

            self.alerted.add(key)

            return {

                "attack": "Brute Force",

                "severity": "High",

                "timestamp": event["timestamp"],

                "ip": event["ip"],

                "user": event["user"],

                "failed_attempts": count,

                "recommendation":
                    "Block source IP and investigate account."

            }

        return None