from log_reader import LogReader
from log_parser import LogParser
from detection_engine import DetectionEngine

reader = LogReader(
    "logs/sample_auth.log"
)

parser = LogParser()
engine = DetectionEngine()
logs = reader.read_logs()


for line in logs:
    event = parser.parse(line)
    alerts = engine.analyze(event)
    for alert in alerts:
        print()
        print("=" * 50)
        print("SECURITY ALERT")
        print("=" * 50)
        print(alert)
    
