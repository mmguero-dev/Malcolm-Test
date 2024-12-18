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
    "pcap/protocols/DCERPC.pcap",
    "pcap/protocols/DHCP.pcap",
    "pcap/protocols/DNS.pcap",
    "pcap/protocols/FTP.pcap",
    "pcap/protocols/HTTP_1.pcap",
    "pcap/protocols/HTTP_2.pcap",
    "pcap/protocols/IPsec.pcap",
    "pcap/protocols/IRC.pcap",
    "pcap/protocols/KRB5.pcap",
    "pcap/protocols/LDAP.pcap",
    "pcap/protocols/MySQL.pcap",
    "pcap/protocols/NTLM.pcap",
    "pcap/protocols/NTP.pcap",
    "pcap/protocols/OpenVPN.pcap",
    "pcap/protocols/OSPF.pcap",
    "pcap/protocols/QUIC.pcap",
    "pcap/protocols/RADIUS.pcap",
    "pcap/protocols/RDP.pcap",
    "pcap/protocols/RFB.pcap",
    "pcap/protocols/SIP.pcap",
    "pcap/protocols/SMB.pcap",
    "pcap/protocols/SMTP.pcap",
    "pcap/protocols/SNMP.pcap",
    "pcap/protocols/SSH.pcap",
    "pcap/protocols/SSL.pcap",
    "pcap/protocols/STUN.pcap",
    "pcap/protocols/Syslog.pcap",
    "pcap/protocols/Telnet.pcap",
    "pcap/protocols/TFTP.pcap",
    "pcap/protocols/Tunnels.pcap",
    "pcap/protocols/WireGuard.pcap",
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
    artifact_hash_map,
):
    assert all([artifact_hash_map.get(x, None) for x in mmguero.GetIterable(UPLOAD_ARTIFACTS)])

    response = requests.post(
        f"{malcolm_url}/mapi/agg/event.dataset",
        headers={"Content-Type": "application/json"},
        json={
            "from": "0",
            "filter": {
                "event.provider": "zeek",
                "tags": [artifact_hash_map[x] for x in mmguero.GetIterable(UPLOAD_ARTIFACTS)],
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
    artifact_hash_map,
):
    response = requests.post(
        f"{malcolm_url}/mapi/document",
        headers={"Content-Type": "application/json"},
        json={
            "from": "0",
            "limit": "2",
            "filter": {
                "event.provider": "zeek",
                "tags": [artifact_hash_map[x] for x in mmguero.GetIterable(UPLOAD_ARTIFACTS)],
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


@pytest.mark.mapi
@pytest.mark.pcap
def test_freq(
    malcolm_http_auth,
    malcolm_url,
    artifact_hash_map,
):
    response = requests.post(
        f"{malcolm_url}/mapi/agg/dns.host,event.freq_score_v1,event.freq_score_v2",
        headers={"Content-Type": "application/json"},
        json={
            "from": "0",
            "limit": "10",
            "filter": {
                "event.provider": "zeek",
                "event.dataset": "dns",
                "!event.freq_score_v1": None,
                "!event.freq_score_v2": None,
                "tags": [artifact_hash_map[x] for x in mmguero.GetIterable(UPLOAD_ARTIFACTS)],
            },
        },
        allow_redirects=True,
        auth=malcolm_http_auth,
        verify=False,
    )
    response.raise_for_status()
    freqs = {
        bucket['key']: (
            bucket['event.freq_score_v1']['buckets'][0]['key'],
            bucket['event.freq_score_v1']['buckets'][0]['event.freq_score_v2']['buckets'][0]['key'],
        )
        for bucket in response.json().get('dns.host').get('buckets')
    }
    LOGGER.debug(freqs)
    assert freqs


@pytest.mark.mapi
@pytest.mark.pcap
def test_geo_asn(
    malcolm_http_auth,
    malcolm_url,
    artifact_hash_map,
):
    for provider in ('zeek', 'suricata'):
        for field in ('destination.geo.city_name', 'source.geo.city_name', 'destination.as.full', 'source.as.full'):
            response = requests.post(
                f"{malcolm_url}/mapi/agg/event.provider,{field}",
                headers={"Content-Type": "application/json"},
                json={
                    "from": "0",
                    "filter": {
                        "event.provider": provider,
                        f"!{field}": None,
                        "tags": [artifact_hash_map[x] for x in mmguero.GetIterable(UPLOAD_ARTIFACTS)],
                    },
                },
                allow_redirects=True,
                auth=malcolm_http_auth,
                verify=False,
            )
            response.raise_for_status()
            items = [x['key'] for x in response.json()['event.provider']['buckets'][0][field]['buckets']]
            LOGGER.debug({provider: {field: items}})
            assert items


@pytest.mark.mapi
@pytest.mark.pcap
def test_conn_info(
    malcolm_http_auth,
    malcolm_url,
    artifact_hash_map,
):
    for provider in ['zeek']:
        for field in (
            'source.oui',
            'destination.oui',
            'related.oui',
            'network.direction',
            'network.transport',
            'network.iana_number',
            'user_agent.original',
        ):
            response = requests.post(
                f"{malcolm_url}/mapi/agg/event.provider,{field}",
                headers={"Content-Type": "application/json"},
                json={
                    "from": "0",
                    "filter": {
                        "event.provider": provider,
                        f"!{field}": None,
                        "tags": [artifact_hash_map[x] for x in mmguero.GetIterable(UPLOAD_ARTIFACTS)],
                    },
                },
                allow_redirects=True,
                auth=malcolm_http_auth,
                verify=False,
            )
            response.raise_for_status()
            item = [x['key'] for x in response.json()['event.provider']['buckets'][0][field]['buckets']]
            LOGGER.debug({provider: {field: item}})
            assert item
