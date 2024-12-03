import mmguero
import requests
import logging

LOGGER = logging.getLogger(__name__)

UPLOAD_ARTIFACTS = [
    "DCERPC.pcap",
    "DHCP.pcap",
    "DNS.pcap",
    "FTP.pcap",
    "HTTP_1.pcap",
    "HTTP_2.pcap",
    "IPsec.pcap",
    "IRC.pcap",
    "KRB5.pcap",
    "LDAP.pcap",
    "MySQL.pcap",
    "NTLM.pcap",
    "NTP.pcap",
    "OpenVPN.pcap",
    "OSPF.pcap",
    "QUIC.pcap",
    "RADIUS.pcap",
    "RDP.pcap",
    "RFB.pcap",
    "SIP.pcap",
    "SMB.pcap",
    "SMTP.pcap",
    "SNMP.pcap",
    "SSH.pcap",
    "SSL.pcap",
    "STUN.pcap",
    "Syslog.pcap",
    "Telnet.pcap",
    "TFTP.pcap",
    "Tunnels.pcap",
    "WireGuard.pcap",
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
