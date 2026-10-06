"""Nmap XML parser tests (no Nmap binary needed)."""

import pytest

from app.services.nmap_parser import NmapParseError, parse_nmap_xml

SINGLE_HOST = """<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.94">
  <host>
    <status state="up" reason="localhost-response"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac"/>
    <hostnames><hostname name="lab-host" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="9.3" method="probed"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="nginx" version="1.27" extrainfo="reverse proxy"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="closed" reason="reset"/>
        <service name="https" method="table"/>
      </port>
      <port protocol="tcp" portid="notaport">
        <state state="open" reason="syn-ack"/>
      </port>
    </ports>
    <os>
      <osmatch name="Linux 6.X" accuracy="95"/>
      <osmatch name="Linux 5.X" accuracy="90"/>
    </os>
  </host>
</nmaprun>
"""

MULTI_HOST = """<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.94">
  <host>
    <status state="up" reason="arp-response"/>
    <address addr="192.168.1.10" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh"/>
      </port>
    </ports>
  </host>
  <host>
    <status state="up" reason="arp-response"/>
    <address addr="192.168.1.11" addrtype="ipv4"/>
  </host>
  <host>
    <status state="down" reason="no-response"/>
    <address addr="192.168.1.12" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

BARE_HOST = """<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.94">
  <host><status state="up" reason="syn-ack"/><address addr="10.0.0.9" addrtype="ipv4"/></host>
</nmaprun>
"""


def test_single_host_full_fields():
    (host,) = parse_nmap_xml(SINGLE_HOST)
    assert host.ip_address == "127.0.0.1"
    assert host.hostname == "lab-host"
    assert host.mac_address == "AA:BB:CC:DD:EE:FF"
    assert host.operating_system == "Linux 6.X"  # highest accuracy wins
    assert host.state == "up"
    # Only open ports with valid ids: 22 + 80 (closed 443 and bad id dropped).
    assert [(service.port, service.service_name) for service in host.services] == [
        (22, "ssh"),
        (80, "http"),
    ]
    ssh, http = host.services
    assert (ssh.product, ssh.version) == ("OpenSSH", "9.3")
    assert http.extra_info == "reverse proxy"
    assert all(service.protocol == "tcp" and service.state == "open" for service in host.services)


def test_multiple_hosts_down_skipped_no_ports_ok():
    hosts = parse_nmap_xml(MULTI_HOST)
    assert [host.ip_address for host in hosts] == ["192.168.1.10", "192.168.1.11"]
    assert len(hosts[0].services) == 1
    assert hosts[1].services == []
    assert hosts[1].hostname is None
    assert hosts[1].mac_address is None
    assert hosts[1].operating_system is None


def test_bare_host_tolerated():
    (host,) = parse_nmap_xml(BARE_HOST)
    assert host.ip_address == "10.0.0.9"
    assert host.services == []


@pytest.mark.parametrize(
    "bad_xml",
    [
        "",
        "   ",
        "<nmaprun><host>",  # truncated
        "<html><body>not nmap</body></html>",  # wrong root
        "PORT STATE SERVICE\n22/tcp open ssh",  # human-readable output rejected
    ],
)
def test_malformed_xml_controlled_failure(bad_xml):
    with pytest.raises(NmapParseError):
        parse_nmap_xml(bad_xml)
