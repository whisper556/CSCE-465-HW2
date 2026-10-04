import struct
from dataclasses import dataclass
 
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac as c_hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
 
# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------
VERSION = 1
DIR_G2N = 0x01              # gateway -> node
DIR_N2G = 0x02              # node -> gateway
 
HEADER_FMT = ">BBQBI"       # version, direction, sequence, message_type, ciphertext_length
HEADER_LEN = struct.calcsize(HEADER_FMT)    # 15
TAG_LEN = 32
MAX_PLAINTEXT = 1 << 20     # 1 MiB cap, checked before any allocation/decryption
 
# --- CTR counter-block layout (see the note in _ctr_block) ----------------
# True  : counter block = session_id || (sequence << 32). Records can be up to
#         2^32 blocks long without their keystreams overlapping. (default)
# False : counter block = iv exactly (session_id || sequence). Literal reading
#         of the assignment, but a record longer than 16 bytes reuses keystream
#         belonging to the next record(s).
SAFE_CTR_BLOCK = True
 
 
# --------------------------------------------------------------------------
# Errors -- every failure is a RecordError; none of them carries plaintext
# --------------------------------------------------------------------------
class RecordError(Exception):
    pass
 
 
class MalformedRecord(RecordError):
    """Too short, bad version, or declared length does not match the data."""
 
 
class WrongDirection(RecordError):
    """Record is labelled for a different direction (e.g. reflected)."""
 
 
class AuthenticationFailed(RecordError):
    """HMAC tag did not verify (modified header/ciphertext/tag, or wrong key)."""
 
 
class SequenceError(RecordError):
    """Sequence number is not the exact next expected value."""
 
 
class ReplayError(SequenceError):
    """Sequence number is older than expected (replay)."""
 
 
class OutOfOrderError(SequenceError):
    """Sequence number is ahead of expected (dropped or reordered record)."""
 
 
# --------------------------------------------------------------------------
# Per-direction state
# --------------------------------------------------------------------------
@dataclass
class Channel:
    """One direction of one session: its keys, direction label, and counter."""
    direction: int
    k_enc: bytes
    k_mac: bytes
    session_id: bytes
    seq: int = 0            # sender: next sequence to use; receiver: next sequence expected
 
 
def make_channels(keys, role):
    """
    Build (send_channel, recv_channel) for `role` ("gateway" or "node")
    from handshake.SessionKeys. Sequence numbers start at 0 in each direction.
    """
    if isinstance(role, bytes):
        role = role.decode()
    g2n = dict(k_enc=keys.k_g2n_enc, k_mac=keys.k_g2n_mac, session_id=keys.session_id)
    n2g = dict(k_enc=keys.k_n2g_enc, k_mac=keys.k_n2g_mac, session_id=keys.session_id)
    if role == "gateway":
        return Channel(DIR_G2N, **g2n), Channel(DIR_N2G, **n2g)
    if role == "node":
        return Channel(DIR_N2G, **n2g), Channel(DIR_G2N, **g2n)
    raise ValueError("role must be 'gateway' or 'node'")
 
 
# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def _make_iv(session_id: bytes, seq: int) -> bytes:
    return session_id + struct.pack(">Q", seq)
 
 
def _ctr_block(iv: bytes) -> bytes:
    """
    Initial CTR counter block for AES-CTR.
 
    CTR increments the whole 128-bit block per 16 bytes of data. If the
    sequence number sits in the low 8 bytes (the literal iv), then block 1 of
    record n uses the same counter value as block 0 of record n+1 -- the two
    records share keystream, and XORing their ciphertexts cancels it (the
    Task 1 two-time-pad problem). Shifting the sequence into the upper 32 bits
    of the low half leaves 32 bits of block counter per record, so keystreams
    never overlap. The `iv` that is authenticated by the MAC is unchanged.
    """
    if not SAFE_CTR_BLOCK:
        return iv
    session_id, seq = iv[:8], struct.unpack(">Q", iv[8:])[0]
    if seq >= 1 << 32:
        raise RecordError("sequence space exhausted for safe CTR layout")
    return session_id + struct.pack(">Q", seq << 32)
 
 
def _aes_ctr(k_enc: bytes, iv: bytes, data: bytes) -> bytes:
    c = Cipher(algorithms.AES(k_enc), modes.CTR(_ctr_block(iv)))
    op = c.encryptor()          # CTR: encryption and decryption are the same operation
    return op.update(data) + op.finalize()
 
 
def _tag(k_mac: bytes, header: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    h = c_hmac.HMAC(k_mac, hashes.SHA256())
    h.update(header + iv + ciphertext)
    return h.finalize()
 
 
# --------------------------------------------------------------------------
# seal()
# --------------------------------------------------------------------------
def seal(ch: Channel, plaintext: bytes, message_type: int = 0) -> bytes:
    """Encrypt-then-MAC one record and advance the sender's sequence number."""
    if not 0 <= message_type <= 0xFF:
        raise ValueError("message_type must fit in one byte")
    if len(plaintext) > MAX_PLAINTEXT:
        raise ValueError("plaintext too large")
    seq = ch.seq
    if seq >= (1 << 32 if SAFE_CTR_BLOCK else (1 << 64) - 1):
        raise RecordError("sequence space exhausted; a new handshake is required")
 
    iv = _make_iv(ch.session_id, seq)
    ciphertext = _aes_ctr(ch.k_enc, iv, plaintext)
    header = struct.pack(HEADER_FMT, VERSION, ch.direction, seq, message_type, len(ciphertext))
    tag = _tag(ch.k_mac, header, iv, ciphertext)
 
    ch.seq = seq + 1            # advance only after the record is fully built: an IV is never reused
    return header + ciphertext + tag
 
 
# --------------------------------------------------------------------------
# open_record()
# --------------------------------------------------------------------------
def open_record(ch: Channel, record: bytes):
    """
    Verify and decrypt one record. Returns (message_type, plaintext).
 
    On ANY error a RecordError is raised, no plaintext is released, and the
    receiver's expected sequence number is NOT advanced.
 
    Order of checks:
      1. structure  (length, version, declared ciphertext length)
      2. direction  (public header field; rejects reflected records early)
      3. HMAC       (constant-time, over header || iv || ciphertext) -- BEFORE decrypting
      4. sequence   (must be exactly the next expected value)
      5. decrypt
    """
    # 1. structure
    if len(record) < HEADER_LEN + TAG_LEN:
        raise MalformedRecord("record too short")
    header = record[:HEADER_LEN]
    version, direction, seq, message_type, clen = struct.unpack(HEADER_FMT, header)
    if version != VERSION:
        raise MalformedRecord("unsupported version")
    if clen > MAX_PLAINTEXT or HEADER_LEN + clen + TAG_LEN != len(record):
        raise MalformedRecord("declared ciphertext length does not match record")
    ciphertext = record[HEADER_LEN:HEADER_LEN + clen]
    tag = record[HEADER_LEN + clen:]
 
    # 2. direction
    if direction != ch.direction:
        raise WrongDirection("record is labelled for a different direction")
 
    # 3. authenticate first (constant-time compare inside the library)
    iv = _make_iv(ch.session_id, seq)
    h = c_hmac.HMAC(ch.k_mac, hashes.SHA256())
    h.update(header + iv + ciphertext)
    try:
        h.verify(tag)
    except InvalidSignature:
        raise AuthenticationFailed("MAC verification failed") from None
 
    # 4. exact next sequence number (authentic record, so `seq` can be trusted)
    if seq < ch.seq:
        raise ReplayError(f"replayed record (seq {seq}, expected {ch.seq})")
    if seq > ch.seq:
        raise OutOfOrderError(f"out-of-order record (seq {seq}, expected {ch.seq})")
 
    # 5. only now decrypt
    plaintext = _aes_ctr(ch.k_enc, iv, ciphertext)
    ch.seq = seq + 1
    return message_type, plaintext
 
 
# --------------------------------------------------------------------------
# Demo
# --------------------------------------------------------------------------
if __name__ == "__main__":
    import handshake
 
    def expect_reject(name, fn):
        try:
            fn()
        except RecordError as e:
            print(f"  [REJECTED] {name}\n             {type(e).__name__}: {e}")
        else:
            print(f"  [!! ACCEPTED] {name}  <-- should not happen")
 
    print("Running handshake to obtain session keys...")
    gw, node = handshake.make_parties()
    keys, _ = handshake.run_handshake(gw, node)
    g_tx, g_rx = make_channels(keys, "gateway")
    n_tx, n_rx = make_channels(keys, "node")
    print(f"session_id = {keys.session_id.hex()}\n")
 
    cmd = b'{"action":"READ","path":"notes.txt"}'
 
    print("Gateway -> Node:")
    rec = seal(g_tx, cmd, message_type=1)
    print(f"  record ({len(rec)} bytes): header={rec[:HEADER_LEN].hex()}")
    print(f"  ciphertext={rec[HEADER_LEN:-TAG_LEN].hex()}")
    print(f"  tag={rec[-TAG_LEN:].hex()}")
    mtype, pt = open_record(n_rx, rec)
    print(f"  node opened: type={mtype} plaintext={pt!r}")
 
    print("\nNode -> Gateway:")
    rec2 = seal(n_tx, b'{"status":"OK"}', message_type=2)
    print(f"  gateway opened: {open_record(g_rx, rec2)}")
 
    print("\nAttacks (each must be rejected, receiver state must not advance):")
    rec3 = seal(g_tx, cmd, message_type=1)      # seq 1, not yet delivered
    ct_flip = bytearray(rec3); ct_flip[HEADER_LEN + 3] ^= 1
    expect_reject("modified ciphertext", lambda: open_record(n_rx, bytes(ct_flip)))
    hdr_flip = bytearray(rec3); hdr_flip[10] ^= 1      # message_type byte
    expect_reject("modified header", lambda: open_record(n_rx, bytes(hdr_flip)))
    tag_flip = bytearray(rec3); tag_flip[-1] ^= 1
    expect_reject("modified tag", lambda: open_record(n_rx, bytes(tag_flip)))
    expect_reject("replay of seq 0", lambda: open_record(n_rx, rec))   # n_rx still expects seq 1
    open_record(n_rx, rec3)
    expect_reject("replay of seq 0 (after delivering seq 1)", lambda: open_record(n_rx, rec))
    expect_reject("reflection: gateway's own record fed back to the gateway",
                  lambda: open_record(g_rx, rec))
    rec5 = seal(g_tx, cmd)                      # seq 2
    rec6 = seal(g_tx, cmd)                      # seq 3
    expect_reject("out-of-order (skipping a record)", lambda: open_record(n_rx, rec6))
    print(f"  node still expects seq {n_rx.seq}; delivering seq 2 -> "
          f"{open_record(n_rx, rec5)[1]!r}")
    print("\nDone.")
 
