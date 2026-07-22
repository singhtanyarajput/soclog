import re


class LogParser:

    def parse(self, log_line):

        pattern = (
            r"(?P<date>\S+)\s+"
            r"(?P<time>\S+)\s+"
            r"(?P<level>\S+)\s+"
            r"(?P<action>.+?)\s+"
            r"user=(?P<user>\S+)\s+"
            r"ip=(?P<ip>\S+)"
        )

        match = re.match(pattern, log_line)

        if not match:
            return None

        event = match.groupdict()

        event["timestamp"] = (
            event["date"] + " " + event["time"]
        )

        del event["date"]
        del event["time"]

        return event