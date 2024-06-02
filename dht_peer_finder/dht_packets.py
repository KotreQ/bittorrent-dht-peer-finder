from enum import Enum
from random import randbytes
from typing import Self

from . import bencode
from .dht_exceptions import *


class KRPCPacketType(Enum):
    QUERY = b"q"
    RESPONSE = b"r"
    ERROR = b"e"


REQUIRED_KRPC_PACKET_FIELDS = {
    KRPCPacketType.QUERY: [b"q", b"a"],
    KRPCPacketType.RESPONSE: [b"r"],
    KRPCPacketType.ERROR: [b"e"],
}


class KRPCQueryType(Enum):
    PING = b"ping"
    FIND_NODE = b"find_node"
    GET_PEERS = b"get_peers"
    ANNOUNCE_PEER = b"announce_peer"


class KRPCPacket:
    packet_type = None

    def __init__(self, transaction_id: bytes | None):
        self.transaction_id = transaction_id
        if self.transaction_id is None:
            self.transaction_id = randbytes(2)
        elif len(self.transaction_id) != 2:
            raise ValueError(f"Invalid transaction id: {self.transaction_id!r}")

    @classmethod
    def from_bencoded(cls, bencoded_data: bytes):
        try:
            data = bencode.decode(bencoded_data)
        except bencode.BencodeDecodingError:
            raise InvalidKRPCEncodedData(
                "Cannot construct KRPC packet from specified data"
            )

        if not isinstance(data, dict):
            raise InvalidKRPCEncodedData("Packet is of invalid data type")

        if b"t" not in data:
            raise InvalidKRPCEncodedData("Packet doesn't contain transaction id")

        transaction_id = data[b"t"]

        if not isinstance(transaction_id, bytes) or len(transaction_id) != 2:
            raise InvalidKRPCEncodedData("Packet contains invalid transaction id")

        if b"y" not in data:
            raise InvalidKRPCEncodedData("Packet doesn't contain 'type' field")

        try:
            packet_type = KRPCPacketType(data[b"y"])
        except ValueError:
            raise InvalidKRPCEncodedData("Packet contains invalid 'type' field")

        for required_field in REQUIRED_KRPC_PACKET_FIELDS[packet_type]:
            if required_field not in data:
                raise InvalidKRPCEncodedData(
                    f"Packed doesn't contain required '{required_field}' field"
                )

        match packet_type:
            case KRPCPacketType.QUERY:
                try:
                    query_type = KRPCQueryType(data[b"q"])
                except ValueError:
                    raise InvalidKRPCEncodedData("Packet contains invalid query type")

                arguments = data[b"a"]

                if not isinstance(arguments, dict):
                    raise InvalidKRPCEncodedData(
                        "Packet contains invalid arguments data type"
                    )

                return KRPCQueryPacket(transaction_id, query_type, arguments)

            case KRPCPacketType.RESPONSE:
                response = data[b"r"]

                if not isinstance(response, dict):
                    raise InvalidKRPCEncodedData(
                        "Packet contains invalid response data type"
                    )

                return KRPCResponsePacket(transaction_id, response)

            case KRPCPacketType.ERROR:
                error = data[b"e"]

                if (
                    not isinstance(error, list)
                    or not isinstance(error[0], int)
                    or not isinstance(error[1], bytes)
                ):
                    raise InvalidKRPCEncodedData(
                        "Packet contains invalid error data type"
                    )

                return KRPCErrorPacket(transaction_id, (error[0], error[1]))

    def same_transaction(self, other: Self) -> bool:
        return self.transaction_id == other.transaction_id

    def to_bencoded(self) -> bytes:
        if self.packet_type is None:
            raise InvalidKRPCPacket("No specific KRPC packet type present")

        data = {}

        data["t"] = self.transaction_id

        data["y"] = self.packet_type.value

        match self.packet_type:
            case KRPCPacketType.QUERY:
                data["q"] = self.query_type.value
                data["a"] = self.arguments
            case KRPCPacketType.RESPONSE:
                data["r"] = self.response
            case KRPCPacketType.ERROR:
                data["e"] = list(self.error)

        return bencode.encode(data)


class KRPCQueryPacket(KRPCPacket):
    packet_type = KRPCPacketType.QUERY

    def __init__(
        self,
        transaction_id: bytes | None,
        query_type: KRPCQueryType,
        arguments: bencode.BencodableDict,
    ):
        super().__init__(transaction_id)
        self.query_type = query_type
        self.arguments = arguments


class KRPCResponsePacket(KRPCPacket):
    packet_type = KRPCPacketType.RESPONSE

    def __init__(self, transaction_id: bytes | None, response: bencode.BencodableDict):
        super().__init__(transaction_id)
        self.response = response


class KRPCErrorPacket(KRPCPacket):
    packet_type = KRPCPacketType.ERROR

    def __init__(self, transaction_id: bytes | None, error: tuple[int, str | bytes]):
        super().__init__(transaction_id)
        self.error = error
