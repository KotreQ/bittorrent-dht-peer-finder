from dht_peer_finder import BitTorrentDHTConnection


def main():
    conn = BitTorrentDHTConnection(("router.bittorrent.com", 6881))
    ping_success = conn.ping()
    print(f"Ping success: {ping_success}")


if __name__ == "__main__":
    main()
