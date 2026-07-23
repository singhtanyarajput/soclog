class BaseDetector:

    def __init__(self, threshold=5):

        self.threshold = threshold

        self.alerted = set()

    def analyze(self, event):
        raise NotImplementedError

    def create_alert(
        self,
        attack,
        severity,
        timestamp,
        source_ip,
        details,
        recommendation,
    ):

        return {

            "attack": attack,

            "severity": severity,

            "timestamp": timestamp,

            "source_ip": source_ip,

            "details": details,

            "recommendation": recommendation,
        }