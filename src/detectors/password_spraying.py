from collections import defaultdict
from detectors.base_detectors import BaseDetector

class PasswordSprayDetector(BaseDetector):

    def __init__(self, threshold=5):

        super().__init__(threshold)

        self.users_by_ip = defaultdict(set)

    def analyze(self, event):

        if event is None:
            return None

        if event["action"] != "Login failed":
            return None

        ip = event["ip"]

        user = event["user"]

        self.users_by_ip[ip].add(user)

        if ip in self.alerted:
            return None

        if len(self.users_by_ip[ip]) >= self.threshold:

            self.alerted.add(ip)

            return self.create_alert(

                attack="Password Spraying",

                severity="High",

                timestamp=event["timestamp"],

                source_ip=ip,

                details=f"{len(self.users_by_ip[ip])} different users targeted from the same IP.",

                recommendation="Investigate repeated authentication attempts across multiple accounts.",

            )

        return None