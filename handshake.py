import hashlib
import hmac
import os
import struct
import warnings
from dataclasses import dataclass
from pathlib import Path
 

#mute warnings
warnings.filterwarnings(
    "ignore",
    message="Diffie-Hellman over finite fields",
    category=Warning,
)
 
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh, padding, rsa
 
# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------
PROTOCOL_LABEL = b"CSCE465-HS-v2"
GROUP_ID = b"ffdhe3072"
KDF_LABEL = b"CSCE465-KDF-v1"
DH_BYTES = 384          # 3072 bits
NONCE_BYTES = 16
ROLE_GATEWAY = b"gateway"
ROLE_NODE = b"node"
N_FIELDS = 8            # label, group, gw id, node id, gw pub, node pub, gw nonce, node nonce
 
DEFAULT_GROUP_FILE = Path(__file__).with_name("ffdhe3072.pem")
 
 
class HandshakeError(Exception):
    """Any handshake failure. The session must be abandoned; no keys are released."""
 
 
# --------------------------------------------------------------------------
# Optional tracing (off by default so tests stay quiet; on in the __main__ demo)
# --------------------------------------------------------------------------
TRACE = False
 
 
def _hx(b: bytes, n: int = 16) -> str:
    """Hex, truncated to the first n bytes for long values."""
    h = b.hex()
    return h if len(b) <= n else f"{h[:2 * n]}... ({len(b)} bytes)"
 
 
def trace(tag: str, msg: str) -> None:
    if TRACE:
        print(f"  [{tag:<7}] {msg}")
 
 
TRANSCRIPT_FIELD_NAMES = ["protocol label", "group id", "gateway identity", "node identity",
                          "gateway DH public", "node DH public", "gateway nonce", "node nonce"]
 
 
# --------------------------------------------------------------------------
# Group parameters and DH helpers
# --------------------------------------------------------------------------
def load_group(path=DEFAULT_GROUP_FILE) -> dh.DHParameters:
    """Load the ffdhe3072 parameter file generated in Lab Preparation."""
    params = serialization.load_pem_parameters(Path(path).read_bytes())
    nums = params.parameter_numbers()
    if nums.p.bit_length() != 3072 or nums.g != 2:
        raise HandshakeError("group file is not a 3072-bit, g=2 (ffdhe3072) group")
    return params
 
 
def int_to_fixed(value: int) -> bytes:
    """384-byte big-endian, left zero-padded."""
    return value.to_bytes(DH_BYTES, "big")
 
 
def validate_dh_public(params: dh.DHParameters, y: int) -> None:
    """Reject degenerate / out-of-subgroup peer values (1, p-1, small-subgroup...)."""
    p = params.parameter_numbers().p
    if not (2 <= y <= p - 2):
        raise HandshakeError("DH public value out of range")
    # ffdhe primes are safe primes: valid public values lie in the order-q subgroup.
    if pow(y, (p - 1) // 2, p) != 1:
        raise HandshakeError("DH public value not in the prime-order subgroup")
 
 
def dh_shared_secret(params, own_priv: dh.DHPrivateKey, peer_y: int) -> bytes:
    """Z as a 384-byte big-endian string."""
    validate_dh_public(params, peer_y)
    peer_pub = dh.DHPublicNumbers(peer_y, params.parameter_numbers()).public_key()
    z_raw = own_priv.exchange(peer_pub)
    return int_to_fixed(int.from_bytes(z_raw, "big"))
 
 
# --------------------------------------------------------------------------
# Canonical (length-prefixed) transcript
# --------------------------------------------------------------------------
def encode_transcript(gw_id: bytes, node_id: bytes,
                      gw_pub: bytes, node_pub: bytes,
                      gw_nonce: bytes, node_nonce: bytes) -> bytes:
    fields = [PROTOCOL_LABEL, GROUP_ID, gw_id, node_id,
              gw_pub, node_pub, gw_nonce, node_nonce]
    return b"".join(struct.pack(">I", len(f)) + f for f in fields)
 
 
def decode_transcript(data: bytes) -> list:
    """Strictly parse a transcript; any malformation is rejected (before hashing)."""
    fields, off = [], 0
    while off < len(data):
        if off + 4 > len(data):
            raise HandshakeError("malformed transcript: truncated length prefix")
        (n,) = struct.unpack_from(">I", data, off)
        off += 4
        if off + n > len(data):
            raise HandshakeError("malformed transcript: declared length exceeds data")
        fields.append(data[off:off + n])
        off += n
    if len(fields) != N_FIELDS:
        raise HandshakeError("malformed transcript: wrong field count")
    label, group, gw_id, node_id, gw_pub, node_pub, gw_n, node_n = fields
    if label != PROTOCOL_LABEL or group != GROUP_ID:
        raise HandshakeError("malformed transcript: wrong label or group")
    if not gw_id or not node_id:
        raise HandshakeError("malformed transcript: empty identity")
    if len(gw_pub) != DH_BYTES or len(node_pub) != DH_BYTES:
        raise HandshakeError("malformed transcript: bad DH public length")
    if len(gw_n) != NONCE_BYTES or len(node_n) != NONCE_BYTES:
        raise HandshakeError("malformed transcript: bad nonce length")
    return fields
 
 
def transcript_hash(transcript: bytes) -> bytes:
    decode_transcript(transcript)       # reject malformed input BEFORE hashing
    return hashlib.sha256(transcript).digest()
 
 
# --------------------------------------------------------------------------
# Signatures: RSA-PSS / SHA-256 over role || TH
# --------------------------------------------------------------------------
def _pss():
    return padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                       salt_length=hashes.SHA256().digest_size)
 
 
def sign_transcript(key: rsa.RSAPrivateKey, role: bytes, th: bytes) -> bytes:
    return key.sign(role + th, _pss(), hashes.SHA256())
 
 
def verify_transcript_sig(pub: rsa.RSAPublicKey, role: bytes, th: bytes, sig: bytes) -> None:
    try:
        pub.verify(sig, role + th, _pss(), hashes.SHA256())
    except InvalidSignature:
        raise HandshakeError("invalid RSA-PSS transcript signature") from None
 
 
def generate_rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=3072)
 
 
# --------------------------------------------------------------------------
# Key derivation (exactly as specified in the assignment)
# --------------------------------------------------------------------------
def _hmac(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()
 
 
@dataclass(frozen=True)
class SessionKeys:
    k_g2n_enc: bytes
    k_g2n_mac: bytes
    k_n2g_enc: bytes
    k_n2g_mac: bytes
    session_id: bytes   # 8 bytes
 
 
def derive_keys(z: bytes, th: bytes) -> SessionKeys:
    k_master = hashlib.sha256(KDF_LABEL + z + th).digest()
    return SessionKeys(
        k_g2n_enc=_hmac(k_master, b"gateway-to-node encryption" + th),
        k_g2n_mac=_hmac(k_master, b"gateway-to-node MAC" + th),
        k_n2g_enc=_hmac(k_master, b"node-to-gateway encryption" + th),
        k_n2g_mac=_hmac(k_master, b"node-to-gateway MAC" + th),
        session_id=_hmac(k_master, b"session identifier" + th)[:8],
    )
 
 
# --------------------------------------------------------------------------
# Wire messages (what an on-path attacker could see / modify)
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class Hello:
    identity: bytes
    dh_public: bytes    # 384-byte big-endian
    nonce: bytes        # 16 bytes
 
 
@dataclass(frozen=True)
class Finish:
    role: bytes         # b"gateway" or b"node"
    signature: bytes
 
 
# --------------------------------------------------------------------------
# A handshake participant
# --------------------------------------------------------------------------
class Party:
    """
    One side of the handshake. Holds its own long-term RSA key, and PINS the
    peer's expected identity and RSA public key (so an unexpected identity or
    wrong key is rejected before the session is accepted).
    """
 
    def __init__(self, role: bytes, identity: bytes,
                 signing_key: rsa.RSAPrivateKey,
                 peer_identity: bytes, peer_public_key: rsa.RSAPublicKey,
                 group: dh.DHParameters):
        if role not in (ROLE_GATEWAY, ROLE_NODE):
            raise ValueError("role must be gateway or node")
        self.role = role
        self.peer_role = ROLE_NODE if role == ROLE_GATEWAY else ROLE_GATEWAY
        self.identity = identity
        self._sign_key = signing_key
        self.peer_identity = peer_identity
        self.peer_pub_key = peer_public_key
        self.group = group
        self.keys = None            # set only when the handshake fully succeeds
 
        # fresh per-session ephemeral values
        self._dh_priv = group.generate_private_key()
        self._dh_pub = int_to_fixed(self._dh_priv.public_key().public_numbers().y)
        self._nonce = os.urandom(NONCE_BYTES)
        self.my_hello = Hello(identity, self._dh_pub, self._nonce)
 
        self._peer_hello = None
        self._transcript = None
        self._th = None
        self._z = None
 
        self.tag = role.decode().upper()
        trace(self.tag, f"identity = {identity.decode()}, expecting peer = {peer_identity.decode()}")
        trace(self.tag, f"fresh ephemeral DH public = {_hx(self._dh_pub)}")
        trace(self.tag, f"fresh nonce = {self._nonce.hex()}")
 
    # -- internal helpers ---------------------------------------------------
    def _check_peer_hello(self, h: Hello) -> None:
        if h.identity != self.peer_identity:
            raise HandshakeError("unexpected peer identity")
        if len(h.dh_public) != DH_BYTES or len(h.nonce) != NONCE_BYTES:
            raise HandshakeError("malformed hello")
        # Reflection: our own hello bounced back at us.
        if h.nonce == self._nonce or h.dh_public == self._dh_pub or h.identity == self.identity:
            raise HandshakeError("reflected handshake message")
        validate_dh_public(self.group, int.from_bytes(h.dh_public, "big"))
        trace(self.tag, f"peer hello OK: identity matches pinned '{h.identity.decode()}', "
                        f"not reflected, DH value in range and in prime-order subgroup")
 
    def _build_transcript(self, gw: Hello, node: Hello) -> bytes:
        return encode_transcript(gw.identity, node.identity,
                                 gw.dh_public, node.dh_public,
                                 gw.nonce, node.nonce)
 
    def _bind(self, gw: Hello, node: Hello, peer_hello: Hello) -> None:
        t = self._build_transcript(gw, node)
        self._transcript = t
        self._th = transcript_hash(t)
        self._z = dh_shared_secret(self.group, self._dh_priv,
                                   int.from_bytes(peer_hello.dh_public, "big"))
        self._peer_hello = peer_hello
        trace(self.tag, f"transcript built and strictly parsed: {len(t)} bytes, 8 length-prefixed fields")
        trace(self.tag, f"TH = SHA-256(transcript) = {self._th.hex()}")
        trace(self.tag, f"DH shared secret Z (384 bytes) = {_hx(self._z)}")
 
    def _my_finish(self) -> Finish:
        sig = sign_transcript(self._sign_key, self.role, self._th)
        trace(self.tag, f"signed (role='{self.role.decode()}' || TH) with RSA-PSS/SHA-256: {_hx(sig, 12)}")
        return Finish(self.role, sig)
 
    def _check_peer_finish(self, f: Finish) -> None:
        if f.role == self.role:
            raise HandshakeError("reflected handshake message (own role)")
        if f.role != self.peer_role:
            raise HandshakeError("unexpected role in finish message")
        verify_transcript_sig(self.peer_pub_key, f.role, self._th, f.signature)
        trace(self.tag, f"peer signature VALID (role='{f.role.decode()}', pinned RSA key)")
 
    def _derive(self) -> None:
        self.keys = derive_keys(self._z, self._th)
        k = self.keys
        trace(self.tag, "K_master = SHA-256('CSCE465-KDF-v1' || Z || TH)  [kept internal]")
        trace(self.tag, f"K_g2n_enc = {_hx(k.k_g2n_enc)}")
        trace(self.tag, f"K_g2n_mac = {_hx(k.k_g2n_mac)}")
        trace(self.tag, f"K_n2g_enc = {_hx(k.k_n2g_enc)}")
        trace(self.tag, f"K_n2g_mac = {_hx(k.k_n2g_mac)}")
        trace(self.tag, f"session_id = {k.session_id.hex()}")
 
    # -- protocol steps -----------------------------------------------------
    # 1. Gateway -> Node:           Hello_G
    # 2. Node    -> Gateway:        Hello_N, Finish_N   (sign "node" || TH)
    # 3. Gateway -> Node:           Finish_G            (sign "gateway" || TH)
    def initiate(self) -> Hello:
        """Gateway step 1."""
        if self.role != ROLE_GATEWAY:
            raise HandshakeError("only the gateway initiates")
        return self.my_hello
 
    def respond(self, hello_g: Hello):
        """Node step 2: returns (Hello_N, Finish_N)."""
        if self.role != ROLE_NODE:
            raise HandshakeError("only the node responds")
        self._check_peer_hello(hello_g)
        self._bind(gw=hello_g, node=self.my_hello, peer_hello=hello_g)
        return self.my_hello, self._my_finish()
 
    def process_response(self, hello_n: Hello, finish_n: Finish) -> Finish:
        """Gateway step 3: verify node, derive keys, return Finish_G."""
        if self.role != ROLE_GATEWAY:
            raise HandshakeError("only the gateway processes the node response")
        self._check_peer_hello(hello_n)
        self._bind(gw=self.my_hello, node=hello_n, peer_hello=hello_n)
        self._check_peer_finish(finish_n)
        self._derive()      # only after verification
        return self._my_finish()
 
    def process_finish(self, finish_g: Finish) -> None:
        """Node step 4: verify gateway, derive keys."""
        if self.role != ROLE_NODE or self._th is None:
            raise HandshakeError("finish received in wrong state")
        self._check_peer_finish(finish_g)
        self._derive()
 
 
# --------------------------------------------------------------------------
# Convenience: run a full honest handshake
# --------------------------------------------------------------------------
GATEWAY_ID = b"gateway-01"
NODE_ID = b"node-01"
 
 
def make_parties(group=None, gw_key=None, node_key=None):
    group = group or load_group()
    gw_key = gw_key or generate_rsa_key()
    node_key = node_key or generate_rsa_key()
    gw = Party(ROLE_GATEWAY, GATEWAY_ID, gw_key, NODE_ID, node_key.public_key(), group)
    node = Party(ROLE_NODE, NODE_ID, node_key, GATEWAY_ID, gw_key.public_key(), group)
    return gw, node
 
 
def run_handshake(gw: Party, node: Party):
    """Honest in-process run; returns (gateway_keys, node_keys)."""
    hello_g = gw.initiate()
    hello_n, finish_n = node.respond(hello_g)
    finish_g = gw.process_response(hello_n, finish_n)
    node.process_finish(finish_g)
    return gw.keys, node.keys
 
 
def _expect_reject(name, fn):
    try:
        fn()
    except HandshakeError as e:
        print(f"  [REJECTED] {name}\n             reason: {e}")
    else:
        print(f"  [!! ACCEPTED] {name}  <-- should not happen")
 
 
if __name__ == "__main__":
    import sys
    from dataclasses import replace
 
    def banner(t):
        print("\n" + "=" * 70 + f"\n{t}\n" + "=" * 70)
 
    banner("SETUP")
    group = load_group()
    p = group.parameter_numbers().p
    print(f"  Loaded ffdhe3072 group: p is {p.bit_length()} bits, g = 2")
    print("  Generating long-term 3072-bit RSA signing keys (gateway, node)...")
    gw_key, node_key = generate_rsa_key(), generate_rsa_key()
    print("  Each side pins the other's RSA public key and expected identity.")
 
    banner("HONEST HANDSHAKE")
    TRACE = True
    print("Creating parties (fresh DH key + nonce per session):")
    gw, node = make_parties(group, gw_key, node_key)
 
    print("\nSTEP 1: Gateway -> Node : Hello_G (identity, DH public, nonce)")
    hello_g = gw.initiate()
 
    print("\nSTEP 2: Node processes Hello_G, replies Hello_N + Finish_N")
    hello_n, finish_n = node.respond(hello_g)
 
    print("\nSTEP 3: Gateway processes Hello_N + Finish_N, replies Finish_G")
    finish_g = gw.process_response(hello_n, finish_n)
 
    print("\nSTEP 4: Node processes Finish_G")
    node.process_finish(finish_g)
 
    banner("TRANSCRIPT (as seen by the gateway)")
    t = gw._transcript
    off = 0
    for name, field in zip(TRANSCRIPT_FIELD_NAMES, decode_transcript(t)):
        print(f"  4-byte len={len(field):<4} | {name:<18} | {_hx(field, 12)}")
    print(f"  Total {len(t)} bytes; gateway and node transcripts identical: "
          f"{gw._transcript == node._transcript}")
 
    banner("RESULT")
    assert gw.keys == node.keys
    print("  Both sides derived IDENTICAL keys and session_id:", gw.keys.session_id.hex())
    print("  Direction keys are all distinct (key separation):",
          len({gw.keys.k_g2n_enc, gw.keys.k_g2n_mac, gw.keys.k_n2g_enc, gw.keys.k_n2g_mac}) == 4)
 
    banner("ATTACK DEMOS (each must be rejected)")
    TRACE = False
 
    def fresh():
        return make_parties(group, gw_key, node_key)
 
    # (a) attacker flips a bit in the node's nonce
    g, n = fresh()
    hg = g.initiate(); hn, fn = n.respond(hg)
    bad = replace(hn, nonce=bytes([hn.nonce[0] ^ 1]) + hn.nonce[1:])
    _expect_reject("(a) modified node nonce in transit",
                   lambda: g.process_response(bad, fn))
 
    # (b) attacker swaps in its own DH public value (classic MITM)
    g, n = fresh()
    hg = g.initiate(); hn, fn = n.respond(hg)
    mitm_pub = int_to_fixed(group.generate_private_key().public_key().public_numbers().y)
    _expect_reject("(b) MITM substitutes its own DH public value",
                   lambda: g.process_response(replace(hn, dh_public=mitm_pub), fn))
 
    # (c) reflection: gateway's own Hello sent back to it
    g, n = fresh()
    hg = g.initiate(); hn, fn = n.respond(hg)
    _expect_reject("(c) reflected Hello (gateway receives its own Hello)",
                   lambda: g.process_response(hg, fn))
 
    # (d) reflection: node's Finish bounced back to the node
    g, n = fresh()
    hg = g.initiate(); hn, fn = n.respond(hg)
    g.process_response(hn, fn)
    _expect_reject("(d) reflected Finish (node receives its own Finish)",
                   lambda: n.process_finish(fn))
 
    # (e) wrong peer identity
    g, n = fresh()
    hg = g.initiate()
    _expect_reject("(e) unexpected peer identity",
                   lambda: n.respond(replace(hg, identity=b"evil-gateway")))
 
    # (f) peer signs with a different RSA key than the pinned one
    g, n = fresh()
    other = generate_rsa_key()
    imposter = Party(ROLE_NODE, NODE_ID, other, GATEWAY_ID, gw_key.public_key(), group)
    hg = g.initiate(); hn, fn = imposter.respond(hg)
    _expect_reject("(f) signature from an RSA key that is not the pinned key",
                   lambda: g.process_response(hn, fn))
 
    # (g) malformed transcript (declared length too long)
    good = encode_transcript(GATEWAY_ID, NODE_ID, b"\x01" * DH_BYTES, b"\x02" * DH_BYTES,
                             b"\x03" * NONCE_BYTES, b"\x04" * NONCE_BYTES)
    broken = struct.pack(">I", 9999) + good[4:]
    _expect_reject("(g) transcript with an incorrect declared field length",
                   lambda: transcript_hash(broken))
 
    print("\nDone.")
