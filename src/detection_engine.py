from detectors.brute_force import BruteForceDetector
from detectors.password_spraying import PasswordSprayDetector

class DetectionEngine:

    def __init__(self):

        self.detectors = [

            BruteForceDetector(),
            PasswordSprayDetector()

        ]

    def analyze(self, event):

        alerts = []

        for detector in self.detectors:

            alert = detector.analyze(event)

            if alert:

                alerts.append(alert)

        return alerts