import hashlib
import hmac
import struct
from dataclasses import replace
 
import pytest
 
import handshake as hs
 
CMD_PUB = b"\x01" * hs.DH_BYTES
 
 
def _start(parties):
    """Run steps 1-2 and return everything an on-path attacker could see."""
    gw, node = parties
    hello_g = gw.initiate()
    hello_n, finish_n = node.respond(hello_g)
    return gw, node, hello_g, hello_n, finish_n
 
 
def _tlv(fields):
    return b"".join(struct.pack(">I", len(f)) + f for f in fields)
 
 
def _good_fields():
    return [hs.PROTOCOL_LABEL, hs.GROUP_ID, hs.GATEWAY_ID, hs.NODE_ID,
            b"\x01" * hs.DH_BYTES, b"\x02" * hs.DH_BYTES,
            b"\x03" * hs.NONCE_BYTES, b"\x04" * hs.NONCE_BYTES]
 
 
# ---------------------------------------------------------------- test 1: valid handshake
def test_valid_handshake_both_sides_agree(parties):
    gw, node = parties
    kg, kn = hs.run_handshake(gw, node)
    assert kg == kn
    assert len(kg.session_id) == 8
    four = [kg.k_g2n_enc, kg.k_g2n_mac, kg.k_n2g_enc, kg.k_n2g_mac]
    assert all(len(k) == 32 for k in four)
    assert len(set(four)) == 4, "directional enc/MAC keys must all differ (key separation)"
 
 
def test_kdf_matches_assignment_formula(parties):
    gw, node = parties
    kg, _ = hs.run_handshake(gw, node)
    z, th = gw._z, gw._th
    assert len(z) == 384 and len(th) == 32
    k_master = hashlib.sha256(b"CSCE465-KDF-v1" + z + th).digest()
 
    def h(label):
        return hmac.new(k_master, label + th, hashlib.sha256).digest()
 
    assert kg.k_g2n_enc == h(b"gateway-to-node encryption")
    assert kg.k_g2n_mac == h(b"gateway-to-node MAC")
    assert kg.k_n2g_enc == h(b"node-to-gateway encryption")
    assert kg.k_n2g_mac == h(b"node-to-gateway MAC")
    assert kg.session_id == h(b"session identifier")[:8]
 
 
def test_each_session_gets_fresh_keys(group, gw_key, node_key):
    k1, _ = hs.run_handshake(*hs.make_parties(group, gw_key, node_key))
    k2, _ = hs.run_handshake(*hs.make_parties(group, gw_key, node_key))
    assert k1.session_id != k2.session_id
    assert k1.k_g2n_enc != k2.k_g2n_enc
 
 
def test_transcript_is_length_prefixed_in_specified_order(parties):
    gw, node = parties
    hs.run_handshake(gw, node)
    t = gw._transcript
    assert t == node._transcript
    assert struct.unpack(">I", t[:4])[0] == len(hs.PROTOCOL_LABEL)
    assert hs.decode_transcript(t) == [
        hs.PROTOCOL_LABEL, hs.GROUP_ID, hs.GATEWAY_ID, hs.NODE_ID,
        gw.my_hello.dh_public, node.my_hello.dh_public,
        gw.my_hello.nonce, node.my_hello.nonce]
 
 
def test_transcript_encoding_is_unambiguous():
    a = hs.encode_transcript(b"ab", b"c", CMD_PUB, CMD_PUB, b"n" * 16, b"m" * 16)
    b = hs.encode_transcript(b"a", b"bc", CMD_PUB, CMD_PUB, b"n" * 16, b"m" * 16)
    assert a != b, "different field splits must not collide"
 
 
# ---------------------------------------------------------------- malformed transcripts
def _bad_transcripts():
    good = _tlv(_good_fields())
    f = _good_fields()
    return {
        "declared length too long": struct.pack(">I", 9999) + good[4:],
        "truncated length prefix": good + b"\x00\x00",
        "extra field": good + _tlv([b"x"]),
        "missing field": _tlv(f[:-1]),
        "wrong label": _tlv([b"WRONG-LABEL-v2"] + f[1:]),
        "wrong group": _tlv([f[0], b"ffdhe2048"] + f[2:]),
        "short nonce": _tlv(f[:6] + [b"\x03" * 15, f[7]]),
        "short DH public": _tlv(f[:4] + [b"\x01" * 383] + f[5:]),
        "empty identity": _tlv([f[0], f[1], b""] + f[3:]),
    }
 
 
@pytest.mark.parametrize("name", list(_bad_transcripts()))
def test_malformed_transcript_rejected_before_hashing(name):
    with pytest.raises(hs.HandshakeError, match="malformed transcript"):
        hs.transcript_hash(_bad_transcripts()[name])
 
 
# ---------------------------------------------------------------- test 6: handshake attacks
def test_changed_nonce_rejected(parties):
    gw, node, hello_g, hello_n, finish_n = _start(parties)
    bad = replace(hello_n, nonce=bytes([hello_n.nonce[0] ^ 1]) + hello_n.nonce[1:])
    with pytest.raises(hs.HandshakeError, match="invalid RSA-PSS transcript signature"):
        gw.process_response(bad, finish_n)
    assert gw.keys is None
 
 
def test_substituted_dh_public_value_rejected(group, parties):
    gw, node, hello_g, hello_n, finish_n = _start(parties)
    mitm = hs.int_to_fixed(group.generate_private_key().public_key().public_numbers().y)
    with pytest.raises(hs.HandshakeError, match="invalid RSA-PSS transcript signature"):
        gw.process_response(replace(hello_n, dh_public=mitm), finish_n)
    assert gw.keys is None
 
 
def test_hello_modified_on_way_to_node_is_detected(parties):
    gw, node = parties
    hello_g = gw.initiate()
    tampered = replace(hello_g, nonce=bytes([hello_g.nonce[0] ^ 1]) + hello_g.nonce[1:])
    hello_n, finish_n = node.respond(tampered)      # node signs a transcript the gateway never saw
    with pytest.raises(hs.HandshakeError, match="invalid RSA-PSS transcript signature"):
        gw.process_response(hello_n, finish_n)
    assert gw.keys is None
 
 
def test_unexpected_identity_rejected_by_gateway(parties):
    gw, node, hello_g, hello_n, finish_n = _start(parties)
    with pytest.raises(hs.HandshakeError, match="unexpected peer identity"):
        gw.process_response(replace(hello_n, identity=b"evil-node"), finish_n)
    assert gw.keys is None
 
 
def test_unexpected_identity_rejected_by_node(parties):
    gw, node = parties
    with pytest.raises(hs.HandshakeError, match="unexpected peer identity"):
        node.respond(replace(gw.initiate(), identity=b"evil-gateway"))
    assert node.keys is None
 
 
def test_incorrect_rsa_key_rejected(group, gw_key, other_key, parties):
    """Imposter has the right identity string but not the pinned RSA key."""
    gw, _ = parties
    imposter = hs.Party(hs.ROLE_NODE, hs.NODE_ID, other_key,
                        hs.GATEWAY_ID, gw_key.public_key(), group)
    hello_n, finish_n = imposter.respond(gw.initiate())
    with pytest.raises(hs.HandshakeError, match="invalid RSA-PSS transcript signature"):
        gw.process_response(hello_n, finish_n)
    assert gw.keys is None
 
 
def test_corrupted_signature_rejected(parties):
    gw, node, hello_g, hello_n, finish_n = _start(parties)
    sig = bytearray(finish_n.signature)
    sig[-1] ^= 1
    with pytest.raises(hs.HandshakeError, match="invalid RSA-PSS transcript signature"):
        gw.process_response(hello_n, replace(finish_n, signature=bytes(sig)))
 
 
def test_signature_is_bound_to_role(node_key, parties):
    """A node signature made over role 'gateway' must not verify as a node signature."""
    gw, node, hello_g, hello_n, finish_n = _start(parties)
    wrong_role_sig = hs.sign_transcript(node_key, hs.ROLE_GATEWAY, node._th)
    with pytest.raises(hs.HandshakeError, match="invalid RSA-PSS transcript signature"):
        gw.process_response(hello_n, hs.Finish(hs.ROLE_NODE, wrong_role_sig))
 
 
def test_unknown_role_in_finish_rejected(parties):
    gw, node, hello_g, hello_n, finish_n = _start(parties)
    with pytest.raises(hs.HandshakeError, match="unexpected role"):
        gw.process_response(hello_n, replace(finish_n, role=b"admin"))
 
 
def test_reflected_hello_rejected(parties):
    """Gateway is handed its own hello back."""
    gw, node, hello_g, hello_n, finish_n = _start(parties)
    with pytest.raises(hs.HandshakeError, match="unexpected peer identity|reflected"):
        gw.process_response(hello_g, finish_n)
    assert gw.keys is None
 
 
def test_reflected_hello_rejected_even_if_identity_check_would_pass(group, gw_key):
    """Reflection check on nonce/DH value/identity, independent of the identity pin."""
    selfish = hs.Party(hs.ROLE_GATEWAY, hs.GATEWAY_ID, gw_key,
                       hs.GATEWAY_ID, gw_key.public_key(), group)
    with pytest.raises(hs.HandshakeError, match="reflected handshake message"):
        selfish.process_response(selfish.initiate(), hs.Finish(hs.ROLE_NODE, b""))
 
 
def test_reflected_finish_rejected(parties):
    gw, node, hello_g, hello_n, finish_n = _start(parties)
    gw.process_response(hello_n, finish_n)
    with pytest.raises(hs.HandshakeError, match="reflected handshake message"):
        node.process_finish(finish_n)           # node gets its own Finish back
    assert node.keys is None
 
 
def test_finish_from_an_earlier_session_rejected(group, gw_key, node_key):
    """Signature replay: a valid Finish from session 1 is useless in session 2."""
    gw1, node1 = hs.make_parties(group, gw_key, node_key)
    h = gw1.initiate(); hn, fn = node1.respond(h)
    old_finish_g = gw1.process_response(hn, fn)
 
    gw2, node2 = hs.make_parties(group, gw_key, node_key)
    h2 = gw2.initiate(); hn2, fn2 = node2.respond(h2)
    gw2.process_response(hn2, fn2)
    with pytest.raises(hs.HandshakeError, match="invalid RSA-PSS transcript signature"):
        node2.process_finish(old_finish_g)
    assert node2.keys is None
 
 
def _p(group):
    return group.parameter_numbers().p
 
 
@pytest.mark.parametrize("which,pattern", [
    ("zero", "out of range"),
    ("one", "out of range"),
    ("p_minus_1", "out of range"),
    ("p_minus_2", "subgroup"),      # -2 is a non-residue (p = 7 mod 8, p = 3 mod 4)
])
def test_degenerate_dh_public_values_rejected(group, parties, which, pattern):
    p = _p(group)
    y = {"zero": 0, "one": 1, "p_minus_1": p - 1, "p_minus_2": p - 2}[which]
    gw, node = parties
    bad = replace(gw.initiate(), dh_public=hs.int_to_fixed(y))
    with pytest.raises(hs.HandshakeError, match=pattern):
        node.respond(bad)
    assert node.keys is None
 
 
def test_steps_out_of_order_rejected(parties):
    gw, node = parties
    with pytest.raises(hs.HandshakeError):
        node.initiate()                         # only the gateway initiates
    with pytest.raises(hs.HandshakeError):
        node.process_finish(hs.Finish(hs.ROLE_GATEWAY, b""))   # no hello seen yet
 
