from log_reader import LogReader
from log_parser import LogParser
from detectors.brute_force import BruteForceDetector

reader = LogReader(
    "logs/sample_auth.log"
)

parser = LogParser()
detector = BruteForceDetector(threshold=5)
logs = reader.read_logs()


for line in logs:
    event = parser.parse(line)
    alert = detector.analyze(event)
    if alert:
        print("\nALERT")
        print(alert)
    
