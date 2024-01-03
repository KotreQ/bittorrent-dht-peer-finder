import socket
from random import randbytes
from typing import Self

from . import bencode
from .regex import IP_REGEX

NODE_ID_SIZE = 20


def bytes_xor(bytesA: bytes, bytesB: bytes) -> bytes:
    assert len(bytesA) == len(bytesB)
    return bytes([byteA ^ byteB for byteA, byteB in zip(bytesA, bytesB)])


class NodeID:
    def __init__(self, node_id: bytes):
        assert len(node_id) == NODE_ID_SIZE
        self.node_id = node_id

    def distance(self, other: Self):
        byte_distance = bytes_xor(self.node_id, other.node_id)
        return int.from_bytes(byte_distance, "big")


class IpAddrPortInfo:
    def __init__(self, ip: str, port: int):
        ip_match = IP_REGEX.match(ip)
        assert ip_match

        self.ip = list(map(int, ip_match.groups()))
        self.port = port

    @classmethod
    def from_compact(cls, compact: bytes):
        assert len(compact) == 6
        return cls(
            socket.inet_ntop(socket.AF_INET, compact[:4]),
            int.from_bytes(compact[4:], "big"),
        )


class NodeInfo:
    def __init__(self, node_id: NodeID, ip_addr_port: IpAddrPortInfo):
        self.node_id = node_id
        self.ip_addr_port = ip_addr_port

    @classmethod
    def from_compact(cls, compact: bytes):
        assert len(compact) == 26
        return cls(
            NodeID(compact[:NODE_ID_SIZE]),
            IpAddrPortInfo.from_compact(compact[NODE_ID_SIZE:]),
        )


class DHTConnection:
    def __init__(
        self, dht_addr: tuple[str, int], *, max_retries: int = 10, timeout: float = 1
    ):
        self.node_id = randbytes(NODE_ID_SIZE)

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(timeout)

        self.max_retries = max_retries

        self.dht_addr = socket.gethostbyname(dht_addr[0]), dht_addr[1]

    def send_krpc_query(
        self, query_type: str, query_args: bencode.BencodableDict
    ) -> bencode.BencodableDict:
        query_args["id"] = self.node_id

        retries = 0
        while retries <= self.max_retries:
            try:
                transaction_id = randbytes(2)

                request_data = bencode.encode(
                    {
                        "t": transaction_id,
                        "y": "q",  # message type = query
                        "q": query_type,
                        "a": query_args,
                    }
                )

                self.sock.sendto(request_data, self.dht_addr)

                while True:
                    resp_data = self.sock.recv(4096)
                    try:
                        resp_data = bencode.decode(resp_data)
                        if not isinstance(resp_data, dict):
                            raise TypeError(
                                f"Response data: {resp_data!r} is of invalid type: {type(resp_data).__name__}"
                            )
                    except (ValueError, TypeError):
                        continue

                    if resp_data.get(b"t") != transaction_id:
                        continue

                    if resp_data.get(b"y") != b"r":  # message type != response
                        continue

                    if b"r" not in resp_data or not isinstance(resp_data[b"r"], dict):
                        continue

                    return resp_data[b"r"]

            except socket.timeout:
                retries += 1

        raise ConnectionError(f"Max retries exceeded: {self.max_retries}")

    def ping(self) -> bytes:
        resp = self.send_krpc_query("ping", {})
        if b"id" not in resp or not isinstance(resp[b"id"], bytes):
            raise TypeError("Node id not found in ping response")
        return resp[b"id"]
