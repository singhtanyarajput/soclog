from detectors.brute_force import BruteForceDetector


class DetectionEngine:

    def __init__(self):

        self.detectors = [

            BruteForceDetector()

        ]

    def analyze(self, event):

        alerts = []

        for detector in self.detectors:

            alert = detector.analyze(event)

            if alert:

                alerts.append(alert)

        return alerts