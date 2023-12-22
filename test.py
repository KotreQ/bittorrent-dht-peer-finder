from dht_peer_finder import DHTConnection


def main():
    conn = DHTConnection(("router.bittorrent.com", 6881))
    response_id = conn.ping()
    print(f"Response ID: {response_id}")


if __name__ == "__main__":
    main()
