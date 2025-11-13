import ipaddress

from tacacs_server.tacacs.proxy import ProxyHandler


class _ProxyRec:
    def __init__(self, cidr: str):
        self.network = ipaddress.ip_network(cidr)


class _FakeStore:
    def __init__(self, nets: list[str] | None, raise_on_list: bool = False):
        self._nets = nets or []
        self._raise = raise_on_list

    def list_proxies(self):
        if self._raise:
            raise RuntimeError("boom")
        return [_ProxyRec(n) for n in self._nets]


def test_proxy_allowlist_allows_known_proxy_ip():
    store = _FakeStore(["127.0.0.1/32", "10.0.0.0/8"])
    handler = ProxyHandler(device_store=store, validate_sources=True)
    assert handler.validate_proxy_source("127.0.0.1") is True
    assert handler.validate_proxy_source("10.1.2.3") is True


def test_proxy_allowlist_rejects_unknown_proxy_ip():
    store = _FakeStore(["192.168.0.0/16"])
    handler = ProxyHandler(device_store=store, validate_sources=True)
    assert handler.validate_proxy_source("10.1.2.3") is False


def test_proxy_allowlist_fail_open_on_errors():
    store = _FakeStore([], raise_on_list=True)
    handler = ProxyHandler(device_store=store, validate_sources=True)
    # Fail-open returns True when list_proxies raises
    assert handler.validate_proxy_source("10.1.2.3") is True
