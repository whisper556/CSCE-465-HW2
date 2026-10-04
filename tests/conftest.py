from types import SimpleNamespace
 
import pytest
 
import handshake as hs
import secure_record as sr
 
 
@pytest.fixture(scope="session")
def group():
    return hs.load_group()
 
 
@pytest.fixture(scope="session")
def gw_key():
    return hs.generate_rsa_key()
 
 
@pytest.fixture(scope="session")
def node_key():
    return hs.generate_rsa_key()
 
 
@pytest.fixture(scope="session")
def other_key():
    """An RSA key that nobody pinned -- used to play an imposter."""
    return hs.generate_rsa_key()
 
 
@pytest.fixture
def parties(group, gw_key, node_key):
    """Fresh (gateway, node) pair with fresh DH keys and nonces, nothing run yet."""
    return hs.make_parties(group, gw_key, node_key)
 
 
@pytest.fixture
def new_session(group, gw_key, node_key):
    """Factory: run a complete honest handshake and return record-layer channels."""
    def make():
        gw, node = hs.make_parties(group, gw_key, node_key)
        keys, _ = hs.run_handshake(gw, node)
        g_tx, g_rx = sr.make_channels(keys, "gateway")
        n_tx, n_rx = sr.make_channels(keys, "node")
        return SimpleNamespace(keys=keys, g_tx=g_tx, g_rx=g_rx, n_tx=n_tx, n_rx=n_rx)
    return make
 
 
@pytest.fixture
def ch(new_session):
    """Channels for one fresh session: ch.g_tx/g_rx (gateway), ch.n_tx/n_rx (node)."""
    return new_session()
