class LogReader:

    def __init__(self, file_path):

        self.file_path = file_path

    def read_logs(self):

        try:

            with open(
                self.file_path,
                "r",
                encoding="utf-8"
            ) as file:

                logs = file.readlines()

            return logs

        except FileNotFoundError:

            print(f"Log file not found: {self.file_path}")

            return []

        except Exception as error:

            print(f"Error reading log file: {error}")

            return []