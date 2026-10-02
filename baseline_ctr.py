
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

COMMAND = b'{"action":"READ","path":"notes.txt"}'   # fixed-length command (36 bytes)


def xor_bytes(a: bytes, b: bytes) -> bytes:
    assert len(a) == len(b)
    return bytes(x ^ y for x, y in zip(a, b))


def ctr_crypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    """AES-256-CTR. Encryption and decryption are the same operation."""
    c = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
    return c.update(data) + c.finalize()


# ---------------------------------------------------------------- sender
def send(key: bytes, plaintext: bytes) -> bytes:
    iv = os.urandom(16)                       # fresh IV; wire format = iv || ciphertext
    return iv + ctr_crypt(key, iv, plaintext)


# --------------------------------------------------------------- receiver
class Receiver:
    """Decrypts and 'executes' every message it is given. No integrity check,
    no sequence number, no replay detection."""

    def __init__(self, key: bytes):
        self._key = key
        self.executed = []                    # mock side effects

    def receive(self, wire: bytes) -> bytes:
        iv, ct = wire[:16], wire[16:]
        pt = ctr_crypt(self._key, iv, ct)
        self.executed.append(pt)              # "process" the command
        return pt


# ------------------------------------------------------------------ relay
def relay_flip(wire: bytes, known_plain: bytes, old: bytes, new: bytes) -> bytes:
    """
    On-path relay WITHOUT the key. It only knows the (fixed-format) command
    layout, so it knows `old` sits at a given offset. Since
        C = P xor KS   =>   C' = C xor (old xor new) at that offset
    decrypts to P with `old` replaced by `new`.
    """
    assert len(old) == len(new)
    off = known_plain.index(old)
    iv, ct = wire[:16], bytearray(wire[16:])
    delta = xor_bytes(old, new)
    for i, d in enumerate(delta):
        ct[off + i] ^= d
    return iv + bytes(ct)


def show(label: str, b: bytes):
    print(f"{label:<28}{b.hex()}")


if __name__ == "__main__":
    key = os.urandom(32)                      # never given to the relay
    rx = Receiver(key)

    print("=== Step 1: honest sender -> receiver ===")
    wire = send(key, COMMAND)
    print("plaintext sent :", COMMAND)
    print("receiver got   :", rx.receive(wire))

    print("\n=== Step 2: relay bit-flips READ -> WIPE (no key) ===")
    old, new = b"READ", b"WIPE"                # equal length
    tampered = relay_flip(wire, COMMAND, old, new)
    off = COMMAND.index(old)
    c_old = wire[16:][off:off + 4]
    c_new = tampered[16:][off:off + 4]
    show("original ciphertext bytes", c_old)
    show("modified ciphertext bytes", c_new)
    show("C xor C'", xor_bytes(c_old, c_new))
    show("P xor P'  (READ^WIPE)", xor_bytes(old, new))
    assert xor_bytes(c_old, c_new) == xor_bytes(old, new)
    print("=> C xor C' == P xor P' : the relay controls the plaintext change exactly.")
    result = rx.receive(tampered)
    print("receiver got   :", result)
    assert b'"WIPE"' in result

    print("\n=== Step 3: replay the SAME original ciphertext ===")
    rx2 = Receiver(key)
    for n in (1, 2):
        print(f"replay #{n} -> receiver got:", rx2.receive(wire))
    print("times processed:", len(rx2.executed))
    assert len(rx2.executed) == 2

    print("\nNo error was raised for the modification or the replay.")
