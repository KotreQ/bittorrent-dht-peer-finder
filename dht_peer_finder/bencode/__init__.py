type Bencodable = str | int | bytes | list[Bencodable] | BencodableDict
type BencodableDict = dict[str | bytes, Bencodable]


def encode(data: Bencodable) -> bytes:
    if isinstance(data, str):
        data = data.encode()

    if isinstance(data, dict):
        return (
            b"d"
            + b"".join(encode(key) + encode(data[key]) for key in sorted(data))
            + b"e"
        )

    elif isinstance(data, list):
        return b"l" + b"".join(encode(item) for item in data) + b"e"

    elif isinstance(data, int):
        return b"i" + str(data).encode("ascii") + b"e"

    else:
        return str(len(data)).encode("ascii") + b":" + data


def decode(data: bytes) -> Bencodable:
    def parse_int(data: bytes) -> tuple[int, int]:
        end_index = data.index(b"e")
        return int(data[1:end_index]), end_index + 1

    def parse_bytes(data: bytes) -> tuple[bytes, int]:
        colon_index = data.index(b":")
        length = int(data[:colon_index])
        start_index = colon_index + 1
        end_index = start_index + length
        return data[start_index:end_index], end_index

    def parse_list(data: bytes) -> tuple[list[Bencodable], int]:
        result: list[Bencodable] = []
        index = 1
        while data[index] != ord("e"):
            item, index_offset = parse_item(data[index:])
            index += index_offset
            result.append(item)
        return result, index + 1

    def parse_dict(data: bytes) -> tuple[BencodableDict, int]:
        result: BencodableDict = {}
        index = 1
        while data[index] != ord("e"):
            key, index_offset = parse_bytes(data[index:])
            index += index_offset
            value, index_offset = parse_item(data[index:])
            index += index_offset
            result[key] = value
        return result, index + 1

    def parse_item(data: bytes) -> tuple[Bencodable, int]:
        first_char = data[0]

        if first_char == ord("i"):
            return parse_int(data)

        elif first_char == ord("l"):
            return parse_list(data)

        elif first_char == ord("d"):
            return parse_dict(data)

        elif first_char >= ord("0") and first_char <= ord("9"):
            return parse_bytes(data)

        else:
            raise ValueError(f"Invalid bencoded data: {data!r}")

    result, _ = parse_item(data)
    return result
