#!/usr/bin/env python3
"""MikroTik RouterOS API test — connect, login, fetch PPP secrets & active sessions."""

import hashlib
import binascii
import socket
import sys
import struct


def encode_length(length):
    if length < 0x80:
        return struct.pack("!B", length)
    elif length < 0x4000:
        return struct.pack("!H", length | 0x8000)
    elif length < 0x200000:
        return struct.pack("!I", length | 0xC00000)[1:]
    elif length < 0x10000000:
        return struct.pack("!I", length | 0xE0000000)
    else:
        return b"\xf0" + struct.pack("!I", length)


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def decode_length(sock):
    b = recv_exact(sock, 1)
    if not b:
        return None
    b = b[0]
    if b < 0x80:
        return b
    elif b < 0xC0:
        b2 = recv_exact(sock, 1)
        return ((b & 0x3F) << 8) | b2[0] if b2 else None
    elif b < 0xE0:
        rest = recv_exact(sock, 2)
        return ((b & 0x1F) << 16) | (rest[0] << 8) | rest[1] if rest else None
    elif b < 0xF0:
        rest = recv_exact(sock, 3)
        if not rest:
            return None
        return ((b & 0x0F) << 24) | (rest[0] << 16) | (rest[1] << 8) | rest[2]
    else:
        rest = recv_exact(sock, 4)
        if not rest:
            return None
        return (rest[0] << 24) | (rest[1] << 16) | (rest[2] << 8) | rest[3]


def send_sentence(sock, words):
    for word in words:
        encoded = word.encode("utf-8")
        sock.send(encode_length(len(encoded)) + encoded)
    sock.send(b"\x00")


def read_sentence(sock):
    words = []
    while True:
        try:
            length = decode_length(sock)
        except socket.timeout:
            return None
        if length is None:
            return None
        if length == 0:
            return words
        data = recv_exact(sock, length)
        if data is None:
            return None
        words.append(data.decode("utf-8", errors="replace"))


def read_until_done(sock, label):
    print(f"\n{label}")
    print("---")
    result = None
    while True:
        sentence = read_sentence(sock)
        if sentence is None:
            print("  (no more data)")
            break
        if result is None:
            result = sentence
        for word in sentence:
            print(f"  {word}")
        if sentence and sentence[0] in ("!done", "!trap", "!fatal"):
            break
        print()
    print("---")
    return result


def login(sock, user, passwd):
    """Try new-style login (6.43+), fall back to old-style challenge-response."""
    print("\n🔐 Logging in...")

    # Step 1: try new-style (send /login with name + password)
    send_sentence(sock, ["/login", f"=name={user}", f"=password={passwd}"])
    response = read_sentence(sock)

    if response is None:
        print("  ❌ No response from router (timeout)")
        print("  Possible causes:")
        print("    - Wrong port (make sure this is the API port, not Winbox)")
        print("    - API service blocked by 'Available From' or firewall")
        return False

    print("  Response:", response)

    if response[0] == "!done" and len(response) == 1:
        print("  ✅ Login successful (new-style, RouterOS 6.43+)")
        return True

    # Step 2: old-style challenge-response (RouterOS < 6.43)
    # Router replied with !done + =ret=<challenge>
    challenge = None
    for word in response:
        if word.startswith("=ret="):
            challenge = word[5:]
            break

    if challenge:
        print(f"  Challenge received, using old-style login...")
        challenge_bytes = binascii.unhexlify(challenge)
        md5 = hashlib.md5()
        md5.update(b"\x00")
        md5.update(passwd.encode("utf-8"))
        md5.update(challenge_bytes)
        response_hash = "00" + md5.hexdigest()

        send_sentence(sock, ["/login", f"=name={user}", f"=response={response_hash}"])
        response2 = read_sentence(sock)

        if response2 is None:
            print("  ❌ No response to login challenge")
            return False

        print("  Response:", response2)

        if response2[0] == "!done":
            print("  ✅ Login successful (old-style challenge-response)")
            return True
        else:
            print("  ❌ Login failed:", response2)
            return False

    if response[0] == "!trap" or response[0] == "!fatal":
        print("  ❌ Login rejected:", response)
        return False

    print("  ❌ Unexpected response:", response)
    return False


def main():
    if len(sys.argv) != 5:
        print(f"Usage: {sys.argv[0]} <ip> <port> <username> <password>")
        sys.exit(1)

    ip = sys.argv[1]
    port = int(sys.argv[2])
    user = sys.argv[3]
    passwd = sys.argv[4]

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)

    try:
        sock.connect((ip, port))
    except Exception as e:
        print(f"❌ Cannot connect to {ip}:{port}: {e}")
        sys.exit(1)

    print(f"✅ Connected to MikroTik API at {ip}:{port}")

    if not login(sock, user, passwd):
        sock.close()
        sys.exit(1)

    # PPP Secrets
    print("\n📄 Getting PPP Secrets...")
    send_sentence(sock, ["/ppp/secret/print"])
    read_until_done(sock, "📄 PPP Secrets:")

    # Active PPPoE
    print("\n📡 Getting Active PPPoE...")
    send_sentence(sock, ["/ppp/active/print"])
    read_until_done(sock, "📡 Active PPPoE:")

    print("\n🎉 Done.")
    sock.close()


if __name__ == "__main__":
    main()
