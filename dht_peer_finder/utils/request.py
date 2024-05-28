import threading
import time
from collections import deque
from typing import Any


class Request:
    def __init__(self, input_data: Any):
        self.input_data = input_data
        self.is_resolved = False
        self.success = None
        self.result = None

    def resolve(self, result: Any, success: bool = True):
        self.result = result
        self.success = success
        self.is_resolved = True

    def should_process(self):
        return not self.is_resolved

    def get_result(self):
        if self.should_process():  # if not yet processed
            return None

        return self.success, self.result


class TimedRequest(Request):
    def __init__(self, input_data: Any, timeout: float):
        super().__init__(input_data)
        self.timeout = timeout
        self.start_time = time.time()

    def is_timeouted(self):
        return self.start_time + self.timeout < time.time()

    def should_process(self):
        if not super().should_process():
            return False

        if self.is_timeouted():
            self.resolve(None, False)
            return False

        return True


class RequestHandler:
    def __init__(self):
        self._lock = threading.Lock()
        self._queue: deque[Request] = deque()

    def add_request(self, request: Request):
        with self._lock:
            self._queue.append(request)

    def get_request(self) -> Request | None:
        with self._lock:
            while self._queue:
                request = self._queue.popleft()
                if not request.should_process():
                    continue
                self._queue.append(request)
                return request

            return None
