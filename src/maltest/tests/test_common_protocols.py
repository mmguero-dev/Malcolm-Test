import logging
import mmguero
import pytest
import random
import re
import requests
from bs4 import BeautifulSoup
from stream_unzip import stream_unzip, AE_2, AES_256

LOGGER = logging.getLogger(__name__)

# You'll notice I don't use all the PCAPs in pcap/protocols here: I've opted to use some
#   other PCAPs also in the repository which trigger the same parsers but which are smaller
#   and thus faster to process.
UPLOAD_ARTIFACTS = [
    "pcap/other/Digital Bond S4/WinXP.pcap",
    "pcap/plugins/CVE-2021-1675/PrintNightmare.pcap",
    "pcap/plugins/CVE-2021-41773/apache_exploit_success.pcap",
    "pcap/plugins/cve-2021-44228/2021-12-11-thru-13-server-activity-with-log4j-attempts.pcap",
    "pcap/plugins/cve-2021-44228/log4j-attack.pcap",
    "pcap/plugins/smb_mimikatz_copy_to_host.pcap",
    "pcap/plugins/zeek-agenttesla-detector/0e328ab7-12b2-4843-8717-a5b3ebef33a8.pcap",
    "pcap/plugins/zeek-agenttesla-detector/a30789ce-1e1c-4f96-a097-78c34b9fb612.pcap",
    "pcap/plugins/zeek-agenttesla-detector/f9421792-7d2c-47d3-90e0-07eb54ae12fa.pcap",
    "pcap/plugins/zeek-EternalSafety/esteemedaudit-failed-XPSP2.pcap",
    "pcap/plugins/zeek-EternalSafety/eternalchampion.pcap",
    "pcap/protocols/HTTP_websocket.pcap",
    "pcap/protocols/IPsec.pcap",
    "pcap/protocols/IRC.pcap",
    "pcap/protocols/MySQL.pcap",
    "pcap/protocols/OpenVPN.pcap",
    "pcap/protocols/OSPF.pcap",
    "pcap/protocols/PostgreSQL.pcap",
    "pcap/protocols/QUIC.pcap",
    "pcap/protocols/RADIUS.pcap",
    "pcap/protocols/RFB.pcap",
    "pcap/protocols/SSH.pcap",
    "pcap/protocols/SSL.pcap",
    "pcap/protocols/STUN.pcap",
    "pcap/protocols/Synchrophasor.pcap",
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
    "postgresql",
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
def test_common_protocols_zeek(
    malcolm_http_auth,
    malcolm_url,
    artifact_hash_map,
):
    """test_common_protocols_zeek

    Checks for the existence of various Zeek logs (event.dataset)

    Args:
        malcolm_http_auth (HTTPBasicAuth): username and password for the Malcolm instance
        malcolm_url (str): URL for connecting to the Malcolm instance
        artifact_hash_map (defaultdict(lambda: None)): a map of artifact files' full path to their file hash
    """
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
    LOGGER.debug([x for x in EXPECTED_DATASETS if (buckets.get(x, 0) == 0)])
    assert all([(buckets.get(x, 0) > 0) for x in EXPECTED_DATASETS])


@pytest.mark.mapi
@pytest.mark.pcap
def test_mapi_document_lookup(
    malcolm_url,
    malcolm_http_auth,
    artifact_hash_map,
):
    """test_mapi_document_lookup

    Test the /mapi/document API by looking up the JSON document for a zeek log

    Args:
        malcolm_url (str): URL for connecting to the Malcolm instance
        malcolm_http_auth (HTTPBasicAuth): username and password for the Malcolm instance
        artifact_hash_map (defaultdict(lambda: None)): a map of artifact files' full path to their file hash
    """
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
    """test_extracted_files_download

    List the quarantined .exe files from the /extracted-files/quarantine page, then download one of them.
        With the assumption that the downloaded .exe file is zipped (the test suite's default) and
        encrypted with a password of "infected" (the test suite's default), it attempts to decrypt
        and unzip the file.

    Args:
        malcolm_url (str): URL for connecting to the Malcolm instance
        malcolm_http_auth (HTTPBasicAuth): username and password for the Malcolm instance
    """
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
    """test_freq

    Test that the event.freq_score_v1 and event.freq_score_v2 fields were calculated. These fields
        represent the entropy of dns.host values.

    Args:
        malcolm_http_auth (HTTPBasicAuth): username and password for the Malcolm instance
        malcolm_url (str): URL for connecting to the Malcolm instance
        artifact_hash_map (defaultdict(lambda: None)): a map of artifact files' full path to their file hash
    """
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
    """test_geo_asn

    Test that GeoIP and ASN lookups were performed for Zeek and Suricata logs

    Args:
        malcolm_http_auth (HTTPBasicAuth): username and password for the Malcolm instance
        malcolm_url (str): URL for connecting to the Malcolm instance
        artifact_hash_map (defaultdict(lambda: None)): a map of artifact files' full path to their file hash
    """
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
    """test_conn_info

    Check that connection-related enrichment information (source and destination OUIs, direction, transport,
        user agent, etc.) are calculated.

    Args:
        malcolm_http_auth (HTTPBasicAuth): username and password for the Malcolm instance
        malcolm_url (str): URL for connecting to the Malcolm instance
        artifact_hash_map (defaultdict(lambda: None)): a map of artifact files' full path to their file hash
    """
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
