import socket

from ..utils.regex import IP_REGEX

IP_ADDR_PORT_SIZE = 6


class IpAddrPort:
    def __init__(self, ip: str, port: int):
        ip_match = IP_REGEX.match(ip)
        assert ip_match

        self.ip = list(map(int, ip_match.groups()))
        self.port = port

    @classmethod
    def from_compact(cls, compact: bytes):
        assert len(compact) == IP_ADDR_PORT_SIZE
        return cls(
            socket.inet_ntop(socket.AF_INET, compact[:4]),
            int.from_bytes(compact[4:], "big"),
        )

    def to_compact(self) -> bytes:
        ip_packed = socket.inet_pton(socket.AF_INET, ".".join(map(str, self.ip)))
        port_packed = self.port.to_bytes(2, "big")
        return ip_packed + port_packed

    def to_tuple(self):
        return ".".join(map(str, self.ip)), self.port

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, self.__class__):
            raise TypeError(
                f"Object: {other!r} is of invalid type: {type(other).__name__}"
            )
        return self.ip == other.ip and self.port == other.port

    def __hash__(self) -> int:
        return hash(self.to_tuple())
