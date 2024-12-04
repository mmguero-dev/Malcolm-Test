import pytest
import mmguero
import requests
import logging

LOGGER = logging.getLogger(__name__)

UPLOAD_ARTIFACTS = [
    "protocols/DCERPC.pcap",
    "protocols/DHCP.pcap",
    "protocols/DNS.pcap",
    "protocols/FTP.pcap",
    "protocols/HTTP_1.pcap",
    "protocols/HTTP_2.pcap",
    "protocols/IPsec.pcap",
    "protocols/IRC.pcap",
    "protocols/KRB5.pcap",
    "protocols/LDAP.pcap",
    "protocols/MySQL.pcap",
    "protocols/NTLM.pcap",
    "protocols/NTP.pcap",
    "protocols/OpenVPN.pcap",
    "protocols/OSPF.pcap",
    "protocols/QUIC.pcap",
    "protocols/RADIUS.pcap",
    "protocols/RDP.pcap",
    "protocols/RFB.pcap",
    "protocols/SIP.pcap",
    "protocols/SMB.pcap",
    "protocols/SMTP.pcap",
    "protocols/SNMP.pcap",
    "protocols/SSH.pcap",
    "protocols/SSL.pcap",
    "protocols/STUN.pcap",
    "protocols/Syslog.pcap",
    "protocols/Telnet.pcap",
    "protocols/TFTP.pcap",
    "protocols/Tunnels.pcap",
    "protocols/WireGuard.pcap",
]

EXPECTED_DATASETS = [
    "conn",
    "dce_rpc",
    "dhcp",
    "dns",
    "dpd",
    "files",
    "ftp",
    "gquic",
    "http",
    "ipsec",
    "irc",
    "ja4ssh",
    "kerberos",
    "known_certs",
    "known_hosts",
    "known_services",
    "ldap",
    "ldap_search",
    "login",
    "mysql",
    "notice",
    "ntlm",
    "ntp",
    "ocsp",
    "ospf",
    "pe",
    "radius",
    "rdp",
    "rfb",
    "sip",
    "smb_cmd",
    "smb_files",
    "smb_mapping",
    "smtp",
    "snmp",
    "socks",
    "software",
    "ssh",
    "ssl",
    "stun",
    "stun_nat",
    "syslog",
    "tftp",
    "tunnel",
    "websocket",
    "weird",
    "wireguard",
    "x509",
]


@pytest.mark.mapi
@pytest.mark.pcap
def test_common_protocols(
    malcolm_http_auth,
    malcolm_url,
    pcap_hash_map,
):
    assert all([pcap_hash_map.get(x, None) for x in mmguero.GetIterable(UPLOAD_ARTIFACTS)])

    response = requests.post(
        f"{malcolm_url}/mapi/agg/event.dataset",
        headers={"Content-Type": "application/json"},
        json={
            "from": "0",
            "filter": {
                "event.provider": "zeek",
                "tags": [pcap_hash_map[x] for x in mmguero.GetIterable(UPLOAD_ARTIFACTS)],
            },
        },
        allow_redirects=True,
        auth=malcolm_http_auth,
        verify=False,
    )
    response.raise_for_status()
    buckets = {
        item['key']: item['doc_count'] for item in mmguero.DeepGet(response.json(), ['event.dataset', 'buckets'], [])
    }
    LOGGER.info(buckets)
    assert all([(buckets.get(x, 0) > 0) for x in EXPECTED_DATASETS])
