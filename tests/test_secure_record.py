import pytest
 
import secure_record as sr
 
CMD = b'{"action":"READ","path":"notes.txt"}'      # 36 bytes
H = sr.HEADER_LEN                                   # 15
 
 
def flip(data: bytes, index: int, mask: int = 1) -> bytes:
    b = bytearray(data)
    b[index] ^= mask
    return bytes(b)
 
 
def assert_untouched_and_still_usable(rx, good_record, expected_seq=0):
    """After a rejected record the receiver state is unchanged and a genuine record still opens."""
    assert rx.seq == expected_seq
    mtype, pt = sr.open_record(rx, good_record)
    assert pt == CMD
    assert rx.seq == expected_seq + 1
 
 
# ---------------------------------------------------------------- test 1: valid traffic
def test_bidirectional_messages(ch):
    for i in range(5):
        rec = sr.seal(ch.g_tx, CMD + bytes([i]), message_type=1)
        assert sr.open_record(ch.n_rx, rec) == (1, CMD + bytes([i]))
        reply = sr.seal(ch.n_tx, b"OK-%d" % i, message_type=2)
        assert sr.open_record(ch.g_rx, reply) == (2, b"OK-%d" % i)
    assert ch.g_tx.seq == ch.n_rx.seq == ch.n_tx.seq == ch.g_rx.seq == 5
 
 
def test_empty_and_multiblock_plaintexts(ch):
    for pt in (b"", b"x", b"A" * 16, b"B" * 17, b"C" * 1000):
        assert sr.open_record(ch.n_rx, sr.seal(ch.g_tx, pt))[1] == pt
 
 
def test_record_layout(ch):
    rec = sr.seal(ch.g_tx, CMD, message_type=7)
    assert len(rec) == H + len(CMD) + sr.TAG_LEN
    assert rec[0] == sr.VERSION
    assert rec[1] == sr.DIR_G2N
    assert int.from_bytes(rec[2:10], "big") == 0           # sequence starts at zero
    assert rec[10] == 7
    assert int.from_bytes(rec[11:15], "big") == len(CMD)
    assert rec[H:-sr.TAG_LEN] != CMD                        # actually encrypted
 
 
def test_sequence_starts_at_zero_in_each_direction_and_increments(ch):
    seqs_g = [int.from_bytes(sr.seal(ch.g_tx, CMD)[2:10], "big") for _ in range(4)]
    seqs_n = [int.from_bytes(sr.seal(ch.n_tx, CMD)[2:10], "big") for _ in range(4)]
    assert seqs_g == seqs_n == [0, 1, 2, 3]
 
 
def test_keys_are_separate_per_direction_and_purpose(ch):
    keys = {ch.g_tx.k_enc, ch.g_tx.k_mac, ch.n_tx.k_enc, ch.n_tx.k_mac}
    assert len(keys) == 4
    assert ch.g_tx.k_enc == ch.n_rx.k_enc and ch.n_tx.k_mac == ch.g_rx.k_mac
 
 
def test_same_plaintext_gives_different_ciphertext_each_time(ch):
    a, b = sr.seal(ch.g_tx, CMD), sr.seal(ch.g_tx, CMD)
    assert a[H:-sr.TAG_LEN] != b[H:-sr.TAG_LEN]             # IV (sequence) never repeats
 
 
def test_consecutive_records_do_not_share_keystream(ch):
    """Records longer than one AES block must not overlap the next record's keystream."""
    p0, p1 = b"A" * 48, b"B" * 48
    c0 = sr.seal(ch.g_tx, p0)[H:-sr.TAG_LEN]
    c1 = sr.seal(ch.g_tx, p1)[H:-sr.TAG_LEN]
    # If block 1 of record 0 and block 0 of record 1 shared keystream,
    # their ciphertext XOR would equal their plaintext XOR.
    leak = bytes(x ^ y for x, y in zip(c0[16:32], c1[:16])) == bytes(x ^ y for x, y in zip(p0[16:32], p1[:16]))
    assert not leak
 
 
# ---------------------------------------------------------------- test 2: modified ciphertext
@pytest.mark.parametrize("offset", [0, 5, 35])
def test_modified_ciphertext_rejected(ch, offset):
    rec = sr.seal(ch.g_tx, CMD)
    with pytest.raises(sr.AuthenticationFailed):
        sr.open_record(ch.n_rx, flip(rec, H + offset))
    assert_untouched_and_still_usable(ch.n_rx, rec)
 
 
def test_modified_tag_rejected(ch):
    rec = sr.seal(ch.g_tx, CMD)
    with pytest.raises(sr.AuthenticationFailed):
        sr.open_record(ch.n_rx, flip(rec, len(rec) - 1))
    assert_untouched_and_still_usable(ch.n_rx, rec)
 
 
def test_truncated_or_extended_record_rejected(ch):
    rec = sr.seal(ch.g_tx, CMD)
    for bad in (rec[:-1], rec + b"\x00", rec[:H], rec[:5], b""):
        with pytest.raises(sr.MalformedRecord):
            sr.open_record(ch.n_rx, bad)
    assert_untouched_and_still_usable(ch.n_rx, rec)
 
 
def test_bit_flip_cannot_change_command_like_task1(ch):
    """The CTR attack from Task 1 (READ -> WRITE style edit) is now caught by the MAC."""
    rec = sr.seal(ch.g_tx, CMD)
    xor_delta = bytes(a ^ b for a, b in zip(b"READ", b"EXEC"))
    start = H + CMD.index(b"READ")
    forged = bytearray(rec)
    for i, d in enumerate(xor_delta):
        forged[start + i] ^= d
    with pytest.raises(sr.AuthenticationFailed):
        sr.open_record(ch.n_rx, bytes(forged))
 
 
# ---------------------------------------------------------------- test 3: modified header
@pytest.mark.parametrize("index,expected", [
    (0, sr.MalformedRecord),                    # version
    (1, sr.WrongDirection),                     # direction
    *[(i, sr.AuthenticationFailed) for i in range(2, 10)],   # sequence (8 bytes)
    (10, sr.AuthenticationFailed),              # message_type
    *[(i, sr.MalformedRecord) for i in range(11, 15)],       # ciphertext_length (4 bytes)
])
def test_modified_header_rejected(ch, index, expected):
    rec = sr.seal(ch.g_tx, CMD, message_type=1)
    with pytest.raises(expected):
        sr.open_record(ch.n_rx, flip(rec, index))
    assert_untouched_and_still_usable(ch.n_rx, rec)
 
 
def test_changed_message_type_with_old_tag_rejected(ch):
    """Changing message_type and re-using the old tag fails: the tag covers the header."""
    rec = sr.seal(ch.g_tx, CMD, message_type=1)
    forged = rec[:10] + bytes([2]) + rec[11:]
    with pytest.raises(sr.AuthenticationFailed):
        sr.open_record(ch.n_rx, forged)
 
 
# ---------------------------------------------------------------- test 4: replay / ordering
def test_replayed_record_rejected(ch):
    rec = sr.seal(ch.g_tx, CMD)
    assert sr.open_record(ch.n_rx, rec)[1] == CMD
    with pytest.raises(sr.ReplayError):
        sr.open_record(ch.n_rx, rec)
    assert ch.n_rx.seq == 1                      # replay did not move the counter
 
 
def test_old_record_replayed_after_more_traffic(ch):
    first = sr.seal(ch.g_tx, CMD)
    sr.open_record(ch.n_rx, first)
    for _ in range(3):
        sr.open_record(ch.n_rx, sr.seal(ch.g_tx, CMD))
    with pytest.raises(sr.ReplayError):
        sr.open_record(ch.n_rx, first)
    assert ch.n_rx.seq == 4
 
 
def test_skipped_record_rejected_as_out_of_order(ch):
    sr.seal(ch.g_tx, CMD)                        # seq 0 "lost"
    second = sr.seal(ch.g_tx, CMD)               # seq 1
    with pytest.raises(sr.OutOfOrderError):
        sr.open_record(ch.n_rx, second)
    assert ch.n_rx.seq == 0
 
 
def test_record_from_another_session_rejected(new_session):
    a, b = new_session(), new_session()
    rec = sr.seal(a.g_tx, CMD)
    with pytest.raises(sr.AuthenticationFailed):
        sr.open_record(b.n_rx, rec)
 
 
# ---------------------------------------------------------------- test 5: reflection
def test_gateway_record_reflected_to_gateway_rejected(ch):
    rec = sr.seal(ch.g_tx, CMD)
    with pytest.raises(sr.WrongDirection):
        sr.open_record(ch.g_rx, rec)
    assert ch.g_rx.seq == 0
 
 
def test_node_record_reflected_to_node_rejected(ch):
    rec = sr.seal(ch.n_tx, b"OK")
    with pytest.raises(sr.WrongDirection):
        sr.open_record(ch.n_rx, rec)
    assert ch.n_rx.seq == 0
 
 
def test_reflected_record_with_relabelled_direction_rejected(ch):
    """Attacker flips the direction byte to dodge the label check; the MAC key is still wrong."""
    rec = sr.seal(ch.g_tx, CMD)
    relabelled = flip(rec, 1, mask=sr.DIR_G2N ^ sr.DIR_N2G)
    assert relabelled[1] == sr.DIR_N2G
    with pytest.raises(sr.AuthenticationFailed):
        sr.open_record(ch.g_rx, relabelled)
    assert ch.g_rx.seq == 0
 
 
# ---------------------------------------------------------------- Task 3 requirements
def test_mac_verified_before_decrypting(ch, monkeypatch):
    """Decryption must never run on a record that failed authentication."""
    def boom(*a, **k):
        raise AssertionError("decryption ran on an unauthenticated record")
    rec = sr.seal(ch.g_tx, CMD)
    monkeypatch.setattr(sr, "_aes_ctr", boom)
    for bad in (flip(rec, H + 2), flip(rec, 5), flip(rec, len(rec) - 1)):
        with pytest.raises(sr.RecordError):
            sr.open_record(ch.n_rx, bad)
 
 
def test_no_plaintext_released_after_any_error(ch):
    rec = sr.seal(ch.g_tx, CMD)
    attempts = [flip(rec, H + 1), flip(rec, 3), flip(rec, 1), flip(rec, 0), rec[:-1], b""]
    for bad in attempts:
        try:
            result = sr.open_record(ch.n_rx, bad)
        except sr.RecordError:
            continue
        pytest.fail(f"open_record returned {result!r} for a bad record")
 
 
def test_sender_never_reuses_a_sequence_number_or_iv(ch):
    seqs = [int.from_bytes(sr.seal(ch.g_tx, b"x")[2:10], "big") for _ in range(200)]
    assert seqs == list(range(200))
 
 
def test_failed_seal_does_not_advance_sequence(ch):
    with pytest.raises(ValueError):
        sr.seal(ch.g_tx, b"x", message_type=300)
    with pytest.raises(ValueError):
        sr.seal(ch.g_tx, b"x" * (sr.MAX_PLAINTEXT + 1))
    assert ch.g_tx.seq == 0
 
 
def test_absurd_declared_length_rejected_without_allocating(ch):
    rec = sr.seal(ch.g_tx, CMD)
    huge = rec[:11] + (0xFFFFFFFF).to_bytes(4, "big") + rec[15:]
    with pytest.raises(sr.MalformedRecord):
        sr.open_record(ch.n_rx, huge)
 
