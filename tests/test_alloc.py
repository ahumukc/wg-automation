from __future__ import annotations

import pytest

from wgau.alloc import ip_suffix, next_free_ip, next_name, used_suffixes
from wgau.errors import NoFreeIPError


class TestIpSuffix:
    def test_in_base(self):
        assert ip_suffix("10.7.0", "10.7.0.5") == 5

    def test_other_subnet(self):
        assert ip_suffix("10.7.0", "10.8.0.5") is None

    def test_with_cidr_not_matched(self):
        # на входе ожидаются «голые» IP (без /32)
        assert ip_suffix("10.7.0", "10.7.0.5/32") is None

    def test_short_ip(self):
        assert ip_suffix("10.7.0", "10.7.5") is None


class TestUsedSuffixes:
    def test_empty(self):
        assert used_suffixes("10.7.0", []) == set()

    def test_mixed(self):
        ips = ["10.7.0.2", "10.7.0.5", "10.9.0.3", "192.168.1.1"]
        assert used_suffixes("10.7.0", ips) == {2, 5}

    def test_cidr_ignored(self):
        assert used_suffixes("10.7.0", ["10.7.0.5/32"]) == set()


class TestNextFreeIp:
    def test_first_free(self):
        assert next_free_ip("10.7.0", set()) == "10.7.0.2"

    def test_skips_used(self):
        assert next_free_ip("10.7.0", {2, 3}) == "10.7.0.4"

    def test_fills_gap(self):
        assert next_free_ip("10.7.0", {2, 4}) == "10.7.0.3"

    def test_ignores_out_of_range(self):
        # .1 (сервер) и .255 не входят в диапазон 2..254
        assert next_free_ip("10.7.0", {1, 255}) == "10.7.0.2"

    def test_exhausted(self):
        with pytest.raises(NoFreeIPError):
            next_free_ip("10.7.0", set(range(2, 255)))

    def test_custom_bounds(self):
        assert next_free_ip("10.7.0", set(), lo=10, hi=20) == "10.7.0.10"


class TestNextName:
    def test_first(self):
        assert next_name("client", []) == "client1"

    def test_sequential(self):
        assert next_name("client", {"client1", "client2"}) == "client3"

    def test_gap(self):
        assert next_name("client", {"client1", "client3"}) == "client2"

    def test_ignores_other_prefix(self):
        assert next_name("client", {"phone1", "peer2"}) == "client1"