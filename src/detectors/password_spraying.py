from collections import defaultdict


class PasswordSprayDetector:

    def __init__(self, threshold=5):

        self.threshold = threshold

        self.users_by_ip = defaultdict(set)

        self.alerted = set()

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

            return {

                "attack": "Password Spraying",

                "severity": "High",

                "timestamp": event["timestamp"],

                "ip": ip,

                "users_targeted": len(self.users_by_ip[ip]),

                "recommendation":
                    "Investigate repeated authentication attempts across multiple accounts."

            }

        return None