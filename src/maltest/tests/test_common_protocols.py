import logging
import mmguero
import pytest
import random
import re
import requests
from bs4 import BeautifulSoup
from stream_unzip import stream_unzip, AE_2, AES_256

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
    LOGGER.debug(buckets)
    assert all([(buckets.get(x, 0) > 0) for x in EXPECTED_DATASETS])


@pytest.mark.mapi
@pytest.mark.pcap
def test_mapi_document_lookup(
    malcolm_url,
    malcolm_http_auth,
    pcap_hash_map,
):
    response = requests.post(
        f"{malcolm_url}/mapi/document",
        headers={"Content-Type": "application/json"},
        json={
            "from": "0",
            "limit": "2",
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
    docData = response.json()
    LOGGER.debug(docData)
    assert docData.get('results', [])


def zipped_chunks(response, chunk_size=65536):
    for chunk in response.iter_content(chunk_size=chunk_size):
        yield chunk


@pytest.mark.carving
@pytest.mark.webui
@pytest.mark.pcap
def test_extracted_files_download(
    malcolm_url,
    malcolm_http_auth,
):
    response = requests.get(
        f"{malcolm_url}/extracted-files/quarantine",
        allow_redirects=True,
        auth=malcolm_http_auth,
        verify=False,
    )
    response.raise_for_status()
    soup = BeautifulSoup(response.content, 'html.parser')
    exePattern = re.compile(r'\.exe$')
    urls = [link['href'] for link in soup.find_all('a', href=exePattern)]
    LOGGER.debug(urls)
    assert urls
    response = requests.get(
        f"{malcolm_url}/extracted-files/quarantine/{random.choice(urls)}",
        allow_redirects=True,
        auth=malcolm_http_auth,
        verify=False,
    )
    response.raise_for_status()
    assert len(response.content) > 1000
    for fileName, fileSize, unzippedChunks in stream_unzip(
        zipped_chunks(response),
        password=b'infected',
        allowed_encryption_mechanisms=(
            AE_2,
            AES_256,
        ),
    ):
        bytesSize = 0
        with mmguero.TemporaryFilename(suffix='.exe') as exeFileName:
            with open(exeFileName, 'wb') as exeFile:
                for chunk in unzippedChunks:
                    bytesSize = bytesSize + len(chunk)
                    exeFile.write(chunk)
        LOGGER.debug(f"{fileName.decode('utf-8')} {len(response.content)} -> {bytesSize})")
        assert fileName
        assert unzippedChunks
        assert bytesSize
