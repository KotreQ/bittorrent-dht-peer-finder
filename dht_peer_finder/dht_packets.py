from enum import Enum
from random import randbytes
from typing import Self

from . import bencode
from .dht_exceptions import *
from .dht_structures import IP_ADDR_PORT_SIZE, NODE_ID_SIZE, NODE_INFO_SIZE


class KRPCPacketType(Enum):
    QUERY = b"q"
    RESPONSE = b"r"
    ERROR = b"e"


class KRPCMethodType(Enum):
    PING = b"ping"
    FIND_NODE = b"find_node"
    GET_PEERS = b"get_peers"
    ANNOUNCE_PEER = b"announce_peer"


# GENERIC PACKET TYPE
class KRPCPacket:
    PACKET_TYPE = None
    METHOD_TYPE = None

    def __init__(self, transaction_id: bytes | None):
        if transaction_id is None:
            transaction_id = randbytes(2)

        self.transaction_id = transaction_id

    @classmethod
    def from_dict(cls, data: bencode.BencodableDict, transaction_id: bytes | None):
        try:
            packet_type = KRPCPacketType(data.get(b"y"))
        except ValueError:
            raise InvalidKRPCPacket(f"{data!r} has an invalid 'y' key")

        match packet_type:
            case KRPCPacketType.QUERY:
                return KRPCQueryPacket.from_dict(data, transaction_id)
            case KRPCPacketType.RESPONSE:
                return KRPCResponsePacket.from_dict(data, transaction_id)
            case KRPCPacketType.ERROR:
                return KRPCErrorPacket.from_dict(data, transaction_id)

    @classmethod
    def from_bencoded(cls, data: bytes):
        try:
            decoded_data = bencode.decode(data)
        except bencode.BencodeDecodingError:
            raise InvalidKRPCEncodedData(f"{data!r} could not be decoded")

        if not isinstance(decoded_data, dict):
            raise InvalidKRPCEncodedData(f"{data!r} is not a dictionary")

        if b"t" not in decoded_data or not isinstance(decoded_data[b"t"], bytes):
            raise InvalidKRPCPacket(f"{decoded_data!r} has an invalid 't' key")

        transaction_id = decoded_data[b"t"]

        return cls.from_dict(decoded_data, transaction_id)

    def same_transaction(self, other: Self) -> bool:
        return self.transaction_id == other.transaction_id

    def to_bencoded(self):
        data = {}

        data["t"] = self.transaction_id

        if self.PACKET_TYPE is None:
            raise InvalidKRPCPacket("No specific KRPC packet type present")

        data["y"] = self.PACKET_TYPE.value

        match self.PACKET_TYPE:
            case KRPCPacketType.QUERY:
                if self.METHOD_TYPE is None:
                    raise InvalidKRPCPacket("No specific KRPC method type present")
                data["q"] = self.METHOD_TYPE.value
                data["a"] = self.arguments
            case KRPCPacketType.RESPONSE:
                data["r"] = self.return_values
            case KRPCPacketType.ERROR:
                data["e"] = [self.error_code, self.error_msg]

        return bencode.encode(data)


# KRPC PACKET TYPES


class KRPCQueryPacket(KRPCPacket):
    PACKET_TYPE = KRPCPacketType.QUERY

    def __init__(self, arguments: bencode.BencodableDict, transaction_id: bytes | None):
        super().__init__(transaction_id)
        self.arguments = arguments

        if (
            not b"id" in self.arguments
            or not isinstance(self.arguments[b"id"], bytes)
            or len(self.arguments[b"id"]) != NODE_ID_SIZE
        ):
            raise InvalidKRPCPacket(f"{self.arguments!r} has an invalid 'id' key")

    @classmethod
    def from_dict(cls, data: bencode.BencodableDict, transaction_id: bytes | None):
        try:
            method_type = KRPCMethodType(data.get(b"q"))
        except ValueError:
            raise InvalidKRPCPacket(f"{data!r} has an invalid 'q' key")

        if b"a" not in data or not isinstance(data[b"a"], dict):
            raise InvalidKRPCPacket(f"{data!r} has an invalid 'a' key")

        query_arguments = data[b"a"]

        return cls.create_type(method_type)(query_arguments, transaction_id)

    @staticmethod
    def create_type(method_type: KRPCMethodType):
        match method_type:
            case KRPCMethodType.PING:
                return KRPCPingQueryPacket
            case KRPCMethodType.FIND_NODE:
                return KRPCFindNodeQueryPacket
            case KRPCMethodType.GET_PEERS:
                return KRPCGetPeersQueryPacket
            case KRPCMethodType.ANNOUNCE_PEER:
                return KRPCAnnouncePeerQueryPacket


class KRPCResponsePacket(KRPCPacket):
    PACKET_TYPE = KRPCPacketType.RESPONSE

    def __init__(
        self, return_values: bencode.BencodableDict, transaction_id: bytes | None
    ):
        super().__init__(transaction_id)
        self.return_values = return_values

        if (
            not b"id" in self.return_values
            or not isinstance(self.return_values[b"id"], bytes)
            or len(self.return_values[b"id"]) != NODE_ID_SIZE
        ):
            raise InvalidKRPCPacket(f"{self.return_values!r} has an invalid 'id' key")

    @classmethod
    def from_dict(cls, data: bencode.BencodableDict, transaction_id: bytes | None):
        if b"r" not in data or not isinstance(data[b"r"], dict):
            raise InvalidKRPCPacket(f"{data!r} has an invalid 'r' key")

        response_values = data[b"r"]

        return cls(response_values, transaction_id)

    @staticmethod
    def create_type(method_type: KRPCMethodType):
        match method_type:
            case KRPCMethodType.PING:
                return KRPCPingResponsePacket
            case KRPCMethodType.FIND_NODE:
                return KRPCFindNodeResponsePacket
            case KRPCMethodType.GET_PEERS:
                return KRPCGetPeersResponsePacket
            case KRPCMethodType.ANNOUNCE_PEER:
                return KRPCAnnouncePeerResponsePacket


class KRPCErrorPacket(KRPCPacket):
    PACKET_TYPE = KRPCPacketType.ERROR

    def __init__(self, error_code: int, error_msg: str, transaction_id: bytes | None):
        super().__init__(transaction_id)
        self.error_code = error_code
        self.error_msg = error_msg

    @classmethod
    def from_dict(cls, data: bencode.BencodableDict, transaction_id: bytes | None):
        if b"e" not in data or not isinstance(data[b"e"], list) or len(data[b"e"]) != 2:
            raise InvalidKRPCPacket(f"{data!r} has an invalid 'e' key")

        error_code, error_msg = data[b"e"]

        if not isinstance(error_code, int) or not isinstance(error_msg, bytes):
            raise InvalidKRPCPacket(f"{data!r} has an invalid error code or message")

        try:
            error_msg = error_msg.decode()
        except UnicodeDecodeError:
            raise InvalidKRPCPacket(f"{data!r} has a wrongly encoded error message")

        return cls(error_code, error_msg, transaction_id)


# KRPC QUERY TYPES


class KRPCPingQueryPacket(KRPCQueryPacket):
    METHOD_TYPE = KRPCMethodType.PING

    def __init__(self, arguments: bencode.BencodableDict, transaction_id: bytes | None):
        super().__init__(arguments, transaction_id)


class KRPCFindNodeQueryPacket(KRPCQueryPacket):
    METHOD_TYPE = KRPCMethodType.FIND_NODE

    def __init__(self, arguments: bencode.BencodableDict, transaction_id: bytes | None):
        if (
            b"target" not in arguments
            or not isinstance(arguments[b"target"], bytes)
            or len(arguments[b"target"]) != NODE_ID_SIZE
        ):
            raise InvalidKRPCPacket(f"{arguments!r} has an invalid 'target' key")

        super().__init__(arguments, transaction_id)


class KRPCGetPeersQueryPacket(KRPCQueryPacket):
    METHOD_TYPE = KRPCMethodType.GET_PEERS

    def __init__(self, arguments: bencode.BencodableDict, transaction_id: bytes | None):
        if (
            b"info_hash" not in arguments
            or not isinstance(arguments[b"info_hash"], bytes)
            or len(arguments[b"info_hash"]) != 20
        ):
            raise InvalidKRPCPacket(f"{arguments!r} has an invalid 'info_hash' key")

        super().__init__(arguments, transaction_id)


class KRPCAnnouncePeerQueryPacket(KRPCQueryPacket):
    METHOD_TYPE = KRPCMethodType.ANNOUNCE_PEER

    def __init__(self, arguments: bencode.BencodableDict, transaction_id: bytes | None):
        if (
            b"info_hash" not in arguments
            or not isinstance(arguments[b"info_hash"], bytes)
            or len(arguments[b"info_hash"]) != 20
        ):
            raise InvalidKRPCPacket(f"{arguments!r} has an invalid 'info_hash' key")

        if (
            b"port" not in arguments
            or not isinstance(arguments[b"port"], int)
            or arguments[b"port"] < 1
            or arguments[b"port"] > 65535
        ):
            raise InvalidKRPCPacket(f"{arguments!r} has an invalid 'port' key")

        if b"token" not in arguments or not isinstance(arguments[b"token"], bytes):
            raise InvalidKRPCPacket(f"{arguments!r} has an invalid 'token' key")

        if b"implied_port" not in arguments:
            arguments[b"implied_port"] = 0

        elif arguments[b"implied_port"] not in (0, 1):
            raise InvalidKRPCPacket(f"{arguments!r} has an invalid 'implied_port' key")

        super().__init__(arguments, transaction_id)


# KRPC REQUEST TYPES


class KRPCPingResponsePacket(KRPCResponsePacket):
    METHOD_TYPE = KRPCMethodType.PING

    def __init__(
        self, return_values: bencode.BencodableDict, transaction_id: bytes | None
    ):
        super().__init__(return_values, transaction_id)


class KRPCFindNodeResponsePacket(KRPCResponsePacket):
    METHOD_TYPE = KRPCMethodType.FIND_NODE

    def __init__(
        self, return_values: bencode.BencodableDict, transaction_id: bytes | None
    ):
        if (
            b"nodes" not in return_values
            or not isinstance(return_values[b"nodes"], bytes)
            or len(return_values[b"nodes"]) % NODE_INFO_SIZE != 0
        ):
            raise InvalidKRPCPacket(f"{return_values!r} has an invalid 'nodes' key")

        super().__init__(return_values, transaction_id)


class KRPCGetPeersResponsePacket(KRPCResponsePacket):
    METHOD_TYPE = KRPCMethodType.GET_PEERS

    def __init__(
        self, return_values: bencode.BencodableDict, transaction_id: bytes | None
    ):
        if b"token" not in return_values or not isinstance(
            return_values[b"token"], bytes
        ):
            raise InvalidKRPCPacket(f"{return_values!r} has an invalid 'token' key")

        if (
            b"nodes" not in return_values
            or not isinstance(return_values[b"nodes"], bytes)
            or len(return_values[b"nodes"]) % NODE_INFO_SIZE != 0
        ) and (
            b"values" not in return_values
            or not isinstance(return_values[b"values"], list)
            or any(
                not isinstance(peer_info, bytes) or len(peer_info) != IP_ADDR_PORT_SIZE
                for peer_info in return_values[b"values"]
            )
        ):
            raise InvalidKRPCPacket(
                f"{return_values!r} has an invalid 'nodes' or 'values' key"
            )

        super().__init__(return_values, transaction_id)


class KRPCAnnouncePeerResponsePacket(KRPCResponsePacket):
    METHOD_TYPE = KRPCMethodType.ANNOUNCE_PEER

    def __init__(
        self, return_values: bencode.BencodableDict, transaction_id: bytes | None
    ):
        super().__init__(return_values, transaction_id)
