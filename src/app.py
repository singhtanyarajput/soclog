from log_reader import LogReader
from log_parser import LogParser
reader = LogReader(
    "logs/sample_auth.log"
)

parser = LogParser()
logs = reader.read_logs()


for line in logs:
    event = parser.parse(line)

    print(event)
    