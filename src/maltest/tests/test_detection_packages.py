import logging
import mmguero
import pytest
import requests

LOGGER = logging.getLogger(__name__)

# TODO
# corelight/callstranger-detector
# corelight/CVE-2021-31166
# corelight/CVE-2021-42292

UPLOAD_ARTIFACTS = [
    # ncsa/bro-simple-scan
    "pcap/plugins/bro-simple-scan/port_scan.pcap",
    # corelight/CVE-2022-23270-PPTP
    "pcap/plugins/CVE-2022-23270-PPTP/CVE-2022-23270-exploited.pcap",
    # corelight/CVE-2022-24491
    "pcap/plugins/CVE-2022-24491/CVE-2022-24491.pcap",
    # corelight/cve-2022-21907
    "pcap/plugins/cve-2022-21907/constructed.pcap",
    # corelight/CVE-2022-24497
    "pcap/plugins/CVE-2022-24497/CVE-2022-24497.pcap",
    # corelight/cve-2022-22954
    "pcap/plugins/cve-2022-22954/attempt-constructed.pcap",
    "pcap/plugins/cve-2022-22954/successful-constructed.pcap",
    # corelight/CVE-2022-30216
    "pcap/plugins/CVE-2022-30216/successful.pcap",
    # corelight/CVE-2021-1675
    "pcap/plugins/CVE-2021-1675/PrintNightmare.pcap",
    # corelight/CVE-2022-26937
    "pcap/plugins/CVE-2022-26937/CVE-2022-26937-exploited.pcap",
    # corelight/CVE-2020-16898
    "pcap/plugins/CVE-2020-16898/pi3_poc.pcap",
    # corelight/CVE-2021-38647
    "pcap/plugins/CVE-2021-38647/CVE-2021-38647-exploit-craigmunsw-omigod-lab.pcap",
    # corelight/CVE-2021-41773
    "pcap/plugins/CVE-2021-41773/apache_exploit_success.pcap",
    # corelight/CVE-2022-3602
    "pcap/plugins/CVE-2022-3602/spookyssl-merged.pcap",
    # corelight/cve-2020-0601
    "pcap/plugins/cve-2020-0601/exploit.pcap",
    # corelight/cve-2020-13777
    "pcap/plugins/cve-2020-13777/gnutls-tls1.2-vulnerable.pcap",
    # corelight/cve-2021-44228
    "pcap/plugins/cve-2021-44228/log4j-attack.pcap",
    # corelight/cve-2022-26809
    "pcap/plugins/cve-2022-26809/cve-2022-26809-4.pcap",
    # corelight/zeek-strrat-detector
    "pcap/plugins/zeek-strrat-detector/strrat-4423258f-59bc-4a88-bfec-d8ac08c88538.pcap",
    # corelight/zeek-quasarrat-detector
    "pcap/plugins/zeek-quasarrat-detector/09ffabf7-774a-43a3-8c97-68f2046fd385.pcap",
    # corelight/zeek-asyncrat-detector
    "pcap/plugins/zeek-asyncrat-detector/30a385ed-171e-4f15-ac3f-08c96be7bfd1.pcap",
    # corelight/zeek-agenttesla-detector
    "pcap/plugins/zeek-agenttesla-detector/0e328ab7-12b2-4843-8717-a5b3ebef33a8.pcap",
    # corelight/zeek-netsupport-detector
    "pcap/plugins/zeek-netsupport-detector/b5d9853f-0dca-45ef-9532-83feeedcbf42.pcap",
    # corelight/http-more-files-names
    "pcap/plugins/http-more-files-names/http-filename-and-etag.pcap",
    # corelight/ripple20
    "pcap/protocols/HTTP_1.pcap",
    # zeek-EternalSafety
    "pcap/plugins/zeek-EternalSafety/eternalblue-success-unpatched-win7.pcap",
    # precurse/zeek-httpattacks
    "pcap/plugins/zeek-httpattacks/http.trace",
    # corelight/zeek-long-connections
    "pcap/plugins/zeek-long-connections/long_connection.pcap",
    # cybera/zeek-sniffpass
    "pcap/plugins/zeek-sniffpass/http_post.trace",
    # corelight/zeek-xor-exe-plugin
    "pcap/plugins/zeek-xor-exe-plugin/2015-04-09-Nuclear-EK-traffic.pcap",
    # corelight/zerologon
    "pcap/plugins/zerologon/CVE-2020-1472_exploit_win2019.pcap",
    # corelight/hassh
    "pcap/protocols/SSH.pcap",
    # mmguero-dev/bzar
    "pcap/protocols/SMB.pcap",
    # cisagov/acid
    "pcap/protocols/S7comm.pcap",
    # corelight/pingback
    "pcap/plugins/Pingback/Pingback_ICMP.pcap",
    # corelight/SIGRed
    "pcap/plugins/SIGred/sigxploit.pcap",
]


EXPECTED_CATEGORIES = [
    # mmguero-dev/bzar and cisagov/acid
    "ATTACK",
    "ATTACKICS",
    "Signatures",
    # corelight/zeek-agenttesla-detector
    "AgentTesla",
    # corelight/zeek-asyncrat-detector
    "AsyncRAT",
    # corelight/CVE-2022-23270-PPTP
    "CVE202223270",
    # corelight/CVE-2022-24491
    "CVE202224491",
    # corelight/CVE-2022-24497
    "CVE202224497",
    # corelight/CVE-2022-26937
    "CVE202226937",
    # corelight/hassh
    "CVE20223602",
    # corelight/cve-2020-0601
    "CVE_2020_0601",
    # corelight/SIGRed
    "CVE_2020_1350",
    # corelight/cve-2020-13777
    "CVE_2020_13777",
    # corelight/CVE-2020-16898
    "CVE_2020_16898",
    # corelight/CVE-2021-38647
    "CVE_2021_38647",
    # corelight/CVE-2021-41773
    "CVE_2021_41773",
    # corelight/cve-2021-44228
    "CVE_2021_44228",
    # corelight/cve-2022-21907
    "CVE_2022_21907",
    # corelight/cve-2022-26809
    "CVE_2022_26809",
    # corelight/CVE-2022-30216
    "CVE_2022_30216_Detection",
    # zeek-EternalSafety
    "EternalSafety",
    # precurse/zeek-httpattacks
    "HTTPATTACKS",
    # corelight/zeek-long-connections
    "LongConnection",
    # corelight/zeek-netsupport-detector
    "NetSupport",
    # corelight/pingback
    "Pingback",
    # corelight/CVE-2021-1675
    "PrintNightmare",
    # corelight/zeek-quasarrat-detector
    "QuasarRAT",
    # corelight/ripple20
    "Ripple20",
    # ncsa/bro-simple-scan
    "Scan",
    # corelight/zeek-strrat-detector
    "STRRAT",
    # # corelight/cve-2022-22954
    "VMWareRCE2022",
    # corelight/zerologon
    "Zerologon",
]


@pytest.mark.mapi
@pytest.mark.pcap
def test_detection_packages(
    malcolm_http_auth,
    malcolm_url,
    artifact_hash_map,
):
    """test_detection_packages

    Check the rule.category field for various values related to Zeek packages that detect CVEs, etc.

    Args:
        malcolm_http_auth (HTTPBasicAuth): username and password for the Malcolm instance
        malcolm_url (str): URL for connecting to the Malcolm instance
        artifact_hash_map (defaultdict(lambda: None)): a map of artifact files' full path to their file hash
    """
    assert all([artifact_hash_map.get(x, None) for x in mmguero.GetIterable(UPLOAD_ARTIFACTS)])

    response = requests.post(
        f"{malcolm_url}/mapi/agg/rule.category",
        headers={"Content-Type": "application/json"},
        json={
            # lol
            "from": "2000 years ago",
            "filter": {
                "event.provider": "zeek",
                "event.dataset": "notice",
                "tags": [artifact_hash_map[x] for x in mmguero.GetIterable(UPLOAD_ARTIFACTS)],
            },
        },
        allow_redirects=True,
        auth=malcolm_http_auth,
        verify=False,
    )
    response.raise_for_status()
    buckets = {
        item['key']: item['doc_count'] for item in mmguero.DeepGet(response.json(), ['rule.category', 'buckets'], [])
    }
    LOGGER.debug(buckets)
    LOGGER.debug([x for x in EXPECTED_CATEGORIES if (buckets.get(x, 0) == 0)])
    assert all([(buckets.get(x, 0) > 0) for x in EXPECTED_CATEGORIES])


@pytest.mark.mapi
@pytest.mark.pcap
def test_hassh_package(
    malcolm_http_auth,
    malcolm_url,
    artifact_hash_map,
):
    """test_hassh_package

    Test for the presence of zeek.ssh.hassh field generated by the HASSH package

    Args:
        malcolm_http_auth (HTTPBasicAuth): username and password for the Malcolm instance
        malcolm_url (str): URL for connecting to the Malcolm instance
        artifact_hash_map (defaultdict(lambda: None)): a map of artifact files' full path to their file hash
    """
    response = requests.post(
        f"{malcolm_url}/mapi/agg/zeek.ssh.hassh",
        headers={"Content-Type": "application/json"},
        json={
            "from": "0",
            "filter": {
                "tags": artifact_hash_map["pcap/protocols/SSH.pcap"],
                "!zeek.ssh.hassh": None,
            },
        },
        allow_redirects=True,
        auth=malcolm_http_auth,
        verify=False,
    )
    response.raise_for_status()
    buckets = {
        item['key']: item['doc_count'] for item in mmguero.DeepGet(response.json(), ['zeek.ssh.hassh', 'buckets'], [])
    }
    LOGGER.debug(buckets)
    assert buckets


@pytest.mark.mapi
@pytest.mark.pcap
def test_xor_decrypt_package(
    malcolm_http_auth,
    malcolm_url,
    artifact_hash_map,
):
    """test_xor_decrypt_package

    Test for the existence of a file.source value of "XOR decrypted", which is generated by the
        corelight/zeek-xor-exe-plugin package.

    Args:
        malcolm_http_auth (HTTPBasicAuth): username and password for the Malcolm instance
        malcolm_url (str): URL for connecting to the Malcolm instance
        artifact_hash_map (defaultdict(lambda: None)): a map of artifact files' full path to their file hash
    """
    response = requests.post(
        f"{malcolm_url}/mapi/agg/file.path",
        headers={"Content-Type": "application/json"},
        json={
            "from": "0",
            "filter": {
                "tags": artifact_hash_map["pcap/plugins/zeek-xor-exe-plugin/2015-04-09-Nuclear-EK-traffic.pcap"],
                "file.source": "XOR decrypted",
            },
        },
        allow_redirects=True,
        auth=malcolm_http_auth,
        verify=False,
    )
    response.raise_for_status()
    buckets = {
        item['key']: item['doc_count'] for item in mmguero.DeepGet(response.json(), ['file.path', 'buckets'], [])
    }
    LOGGER.debug(buckets)
    assert buckets


@pytest.mark.mapi
@pytest.mark.pcap
def test_http_sniffpass(
    malcolm_http_auth,
    malcolm_url,
    artifact_hash_map,
):
    """test_http_sniffpass

    Check for the existence of the zeek.http.post_username field, which is generated by the cybera/zeek-sniffpass package

    Args:
        malcolm_http_auth (HTTPBasicAuth): username and password for the Malcolm instance
        malcolm_url (str): URL for connecting to the Malcolm instance
        artifact_hash_map (defaultdict(lambda: None)): a map of artifact files' full path to their file hash
    """
    response = requests.post(
        f"{malcolm_url}/mapi/agg/zeek.http.post_username",
        headers={"Content-Type": "application/json"},
        json={
            "from": "0",
            "filter": {
                "tags": artifact_hash_map["pcap/plugins/zeek-sniffpass/http_post.trace"],
                "!zeek.http.post_username": None,
            },
        },
        allow_redirects=True,
        auth=malcolm_http_auth,
        verify=False,
    )
    response.raise_for_status()
    buckets = {
        item['key']: item['doc_count']
        for item in mmguero.DeepGet(response.json(), ['zeek.http.post_username', 'buckets'], [])
    }
    LOGGER.debug(buckets)
    assert buckets
