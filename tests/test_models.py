from wgau.models import KeyPair, Peer, WgInterface


class TestPeer:
    def test_public_key(self):
        assert Peer(params={"PublicKey": "PUB"}).public_key == "PUB"

    def test_psk(self):
        assert Peer(params={"PresharedKey": "PSK"}).psk == "PSK"

    def test_missing(self):
        p = Peer()
        assert p.public_key is None
        assert p.psk is None
        assert p.allowed_ips == []
        assert p.first_ip is None

    def test_allowed_ips_single(self):
        assert Peer(params={"AllowedIPs": "10.7.0.2/32"}).allowed_ips == ["10.7.0.2"]

    def test_allowed_ips_multiple(self):
        p = Peer(params={"AllowedIPs": "10.7.0.2/32, 10.8.0.5/32"})
        assert p.allowed_ips == ["10.7.0.2", "10.8.0.5"]

    def test_first_ip(self):
        p = Peer(params={"AllowedIPs": "10.7.0.2/32,10.7.0.3/32"})
        assert p.first_ip == "10.7.0.2"


class TestWgInterface:
    def test_private_key(self):
        assert WgInterface(params={"PrivateKey": "SEC"}).private_key == "SEC"

    def test_private_key_missing(self):
        assert WgInterface().private_key is None


def test_keypair_fields():
    kp = KeyPair(private_key="a", public_key="b", psk="c")
    assert (kp.private_key, kp.public_key, kp.psk) == ("a", "b", "c")