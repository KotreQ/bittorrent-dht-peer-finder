import threading
from collections import deque
from typing import Any


class Request:
    def __init__(self, input_data: Any):
        self.input_data = input_data
        self.is_resolved = False
        self.output_data = None

    def resolve(self, output_data: Any):
        self.output_data = output_data
        self.is_resolved = True


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
                if request.is_resolved:
                    continue
                self._queue.append(request)
                return request

            return None
