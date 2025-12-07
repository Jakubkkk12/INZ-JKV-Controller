import datetime
from app.heplers.constants import USER_ACTION_LOG_FILE_PATH, DEVELOPER_LOG_FILE_PATH


class UserActionLogger:
    __instance = None
    __log_file_path = USER_ACTION_LOG_FILE_PATH

    def __new__(cls):
        if cls.__instance is None:
            cls.__instance = super(UserActionLogger, cls).__new__(cls)

            try:
                cls.__instance._log_file = open(cls.__log_file_path, 'a', encoding='utf-8')
            except Exception as e:
                print(f"Error log file initialization '{cls.__log_file_path}': {e}")
                cls.__instance._log_file = None

        return cls.__instance

    def _write_to_file(self, formatted_message: str) -> None:
        """Internal method to actually write to the file."""
        if self._log_file:
            self._log_file.write(formatted_message + '\n')
            self._log_file.flush()
        else:
            print(formatted_message)

    def _log(self, message: str, severity: str) -> None:
        """Internal method to prepare formatted message."""
        timestamp: str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._write_to_file(f"[{timestamp}] {severity}: {message}")

    def log_info(self, message: str) -> None:
        """Method to log information message.

        Args:
            message (str): Message to be logged.
        """
        self._log(message, "INFO")

    def log_error(self, message: str) -> None:
        """Method to log error message.

        Args:
            message (str): Message to be logged.
        """
        self._log(message, "ERROR")

    def log_warning(self, message: str) -> None:
        """Method to log warning message.

        Args:
            message (str): Message to be logged.
        """
        self._log(message, "WARNING")


class DeveloperLogger:
    __instance = None
    __log_file_path = DEVELOPER_LOG_FILE_PATH

    def __new__(cls):
        if cls.__instance is None:
            cls.__instance = super(DeveloperLogger, cls).__new__(cls)

            try:
                cls.__instance._log_file = open(cls.__log_file_path, 'a', encoding='utf-8')
            except Exception as e:
                print(f"Error log file initialization '{cls.__log_file_path}': {e}")
                cls.__instance._log_file = None

        return cls.__instance

    def _write_to_file(self, formatted_message: str) -> None:
        """Internal method to actually write to the file."""
        if self._log_file:
            self._log_file.write(formatted_message + '\n')
            self._log_file.flush()
        else:
            print(formatted_message)

    def _log(self, message: str, severity: str) -> None:
        """Internal method to prepare formatted message."""
        timestamp: str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._write_to_file(f"[{timestamp}] {severity}: {message}")

    def log_error(self, message: str) -> None:
        """Method to log error message.

        Args:
            message (str): Message to be logged.
        """
        self._log(message, "ERROR")

    def log_warning(self, message: str) -> None:
        """Method to log warning message.

        Args:
            message (str): Message to be logged.
        """
        self._log(message, "WARNING")