class InvalidArgumentError(Exception):
    """Thrown error for invalid arguments.

    Attributes:
        status_code (int): The status code of the response received
        reason (str): The reason why the requests did fail
    """

    def __init__(self, status_code: int, reason: str):
        self.status_code = status_code
        self.reason = reason
        super().__init__(f"HTTP {status_code}: {reason}")
