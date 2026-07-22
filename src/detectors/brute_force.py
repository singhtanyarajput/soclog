from collections import defaultdict


class BruteForceDetector:

    def __init__(self, threshold=5):

        self.threshold = threshold

        self.failed_attempts = defaultdict(int)
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

        self.failed_attempts[key] += 1

        count = self.failed_attempts[key]
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