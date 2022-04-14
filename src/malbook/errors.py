
class Error(BaseException):
    _message: str

    def __init__(self, message: str):
        self._message = message

    def __str__(self) -> str:
        return self._message


class CommandError(Error):
    _output: str

    def __init__(self, message: str, output: str):
        super().__init__(message)
        self._output = output

    def __str__(self) -> str:
        return f'{self._message}\noutput:\n{self._output}'


class DependencyError(Error):
    pass
