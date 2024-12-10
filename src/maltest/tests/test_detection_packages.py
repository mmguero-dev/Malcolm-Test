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
    "plugins/bro-simple-scan/445_scan.pcap",
    "plugins/bro-simple-scan/backscatter.trace",
    "plugins/bro-simple-scan/multiport_scan.pcap",
    "plugins/bro-simple-scan/port_scan.pcap",
    "plugins/bro-simple-scan/scan_with_zero_windows.pcap",
    # corelight/CVE-2022-23270-PPTP
    "plugins/CVE-2022-23270-PPTP/CVE-2022-23270-exploited.pcap",
    # corelight/CVE-2022-24491
    "plugins/CVE-2022-24491/CVE-2022-24491.pcap",
    # corelight/cve-2022-21907
    "plugins/cve-2022-21907/constructed.pcap",
    # corelight/CVE-2022-24497
    "plugins/CVE-2022-24497/CVE-2022-24497.pcap",
    # corelight/cve-2022-22954
    "plugins/cve-2022-22954/attempt-constructed.pcap",
    "plugins/cve-2022-22954/successful-constructed.pcap",
    # corelight/CVE-2022-30216
    "plugins/CVE-2022-30216/successful.pcap",
    "plugins/CVE-2022-30216/unsuccessful.pcap",
    # corelight/CVE-2021-1675
    "plugins/CVE-2021-1675/cve-2021-1675.pcap",
    "plugins/CVE-2021-1675/packetcapture_1.pcap",
    "plugins/CVE-2021-1675/packetcapture_2.pcap",
    "plugins/CVE-2021-1675/PrintNightmare.pcap",
    # corelight/CVE-2022-26937
    "plugins/CVE-2022-26937/CVE-2022-26937-exploited.pcap",
    "plugins/CVE-2022-26937/http.pcap",
    # corelight/CVE-2020-16898
    "plugins/CVE-2020-16898/6in4-linklocal-hlimit-less255.pcap",
    "plugins/CVE-2020-16898/RS-RA.pcap",
    "plugins/CVE-2020-16898/ipv6-neighbor-discovery.pcap",
    "plugins/CVE-2020-16898/ipv6-router-advertisement-leaving.pcap",
    "plugins/CVE-2020-16898/pi3_poc.pcap",
    # corelight/CVE-2021-38647
    "plugins/CVE-2021-38647/CVE-2021-38647-exploit-craigmunsw-omigod-lab.pcap",
    # corelight/CVE-2021-41773
    "plugins/CVE-2021-41773/apache_exploit_success.pcap",
    # corelight/CVE-2022-3602
    "plugins/CVE-2022-3602/sample_OpenSSLv3.0.5.pcap",
    "plugins/CVE-2022-3602/spookyssl-merged.pcap",
    # corelight/cve-2020-0601
    "plugins/cve-2020-0601/broken.pcap",
    "plugins/cve-2020-0601/ecdsa-cert.pcap",
    "plugins/cve-2020-0601/explicit.pcap",
    "plugins/cve-2020-0601/exploit.pcap",
    # corelight/cve-2020-13777
    "plugins/cve-2020-13777/chrome-34-google.trace",
    "plugins/cve-2020-13777/gnutls-tls1.2-non-vulnerable.pcap",
    "plugins/cve-2020-13777/gnutls-tls1.2-vulnerable.pcap",
    "plugins/cve-2020-13777/gnutls-tls1.3.pcap",
    # corelight/cve-2021-44228
    "plugins/cve-2021-44228/2021-12-11-thru-13-server-activity-with-log4j-attempts.pcap",
    "plugins/cve-2021-44228/log4j-attack.pcap",
    "plugins/cve-2021-44228/log4j-dns_exfil.pcap",
    "plugins/cve-2021-44228/log4j-user_agent.pcap",
    "plugins/cve-2021-44228/log4j-webapp.pcap",
    "plugins/cve-2021-44228/spcap-CEXKLs3NQWdEM2CoMj-1639421287179170294-1.pcap",
    # corelight/cve-2022-26809
    "plugins/cve-2022-26809/cve-2022-26809-4.pcap",
    # corelight/zeek-strrat-detector
    "plugins/zeek-strrat-detector/strrat-4423258f-59bc-4a88-bfec-d8ac08c88538.pcap",
    # corelight/zeek-quasarrat-detector
    "plugins/zeek-quasarrat-detector/09ffabf7-774a-43a3-8c97-68f2046fd385.pcap",
    # corelight/zeek-asyncrat-detector
    "plugins/zeek-asyncrat-detector/30a385ed-171e-4f15-ac3f-08c96be7bfd1.pcap",
    "plugins/zeek-asyncrat-detector/9596cf60-0da6-47a7-a375-1f25ae32d843.pcap",
    "plugins/zeek-asyncrat-detector/cd010953-5faf-4054-86be-58c020c3a532.pcap",
    # corelight/zeek-agenttesla-detector
    "plugins/zeek-agenttesla-detector/0e328ab7-12b2-4843-8717-a5b3ebef33a8.pcap",
    "plugins/zeek-agenttesla-detector/a30789ce-1e1c-4f96-a097-78c34b9fb612.pcap",
    "plugins/zeek-agenttesla-detector/db9f075c-7879-4957-923a-f79fac957a2d.pcap",
    "plugins/zeek-agenttesla-detector/f9421792-7d2c-47d3-90e0-07eb54ae12fa.pcap",
    # corelight/zeek-netsupport-detector
    "plugins/zeek-netsupport-detector/b5d9853f-0dca-45ef-9532-83feeedcbf42.pcap",
    # corelight/http-more-files-names
    "plugins/http-more-files-names/favicon.pcap",
    "plugins/http-more-files-names/http-etag-and-filename.pcap",
    "plugins/http-more-files-names/http-filename-and-etag.pcap",
    "plugins/http-more-files-names/http-filename.pcap",
    # corelight/ripple20
    "protocols/HTTP_1.pcap",
    "plugins/ripple20/dns_caa_records.pcap",
    "plugins/ripple20/dns_hip_invalid_character.pcap",
    "plugins/ripple20/dns_long_cname.pcap",
    "plugins/ripple20/dns_over_tcp.pcap",
    "plugins/ripple20/dns_over_udp_with_edns_5000_bytes.pcap",
    "plugins/ripple20/dns_over_udp_with_edns.pcap",
    "plugins/ripple20/dns_over_udp_without_edns.pcap",
    "plugins/ripple20/ipv6_rh0_poc.pcap",
    "plugins/ripple20/dns_variant_1.pcap",
    "plugins/ripple20/dns_variant_2.pcap",
    # zeek-EternalSafety
    "plugins/zeek-EternalSafety/doublepulsar-backdoor-connect-win7.pcap",
    "plugins/zeek-EternalSafety/esteemedaudit-failed-XPSP2.pcap",
    "plugins/zeek-EternalSafety/eternalblue-failed-patched-win7.pcap",
    "plugins/zeek-EternalSafety/eternalblue-success-unpatched-win7.pcap",
    "plugins/zeek-EternalSafety/eternalchampion.pcap",
    "plugins/zeek-EternalSafety/eternalromance-doublepulsar-meterpreter.pcap",
    "plugins/zeek-EternalSafety/eternalromance-success-2008r2.pcap",
    "plugins/zeek-EternalSafety/metasploit-ms017-010-win7x64.pcap",
    "plugins/zeek-EternalSafety/wannacry.pcap",
    # precurse/zeek-httpattacks
    "plugins/zeek-httpattacks/http.trace",
    # cybera/zeek-sniffpass
    "plugins/zeek-sniffpass/http_post.trace",
    # corelight/zeek-xor-exe-plugin
    "plugins/zeek-xor-exe-plugin/2015-04-09-Nuclear-EK-traffic.pcap",
    # corelight/zerologon
    "plugins/zerologon/CVE-2020-1472_exploit_win2016.pcap",
    "plugins/zerologon/CVE-2020-1472_exploit_win2019.pcap",
    "plugins/zerologon/CVE-2020-1472_test_win2016.pcap",
    "plugins/zerologon/CVE-2020-1472_test_win2019.pcap",
    "plugins/download_over_dns.pcap",
    "plugins/smb_mimikatz_copy_to_host.pcap",
    # corelight/hassh
    "protocols/SSH.pcap",
    # mmguero-dev/bzar
    "protocols/SMB.pcap",
    # cisagov/acid
    "protocols/BACnet.pcap",
    "protocols/ENIP.pcap",
    "protocols/S7comm.pcap",
    # corelight/pingback
    "plugins/Pingback/Pingback_ICMP.pcap",
    # corelight/SIGRed
    "plugins/SIGred/sigxploit.pcap",
    "plugins/SIGred/cve-2020-1350.pcap",
    "plugins/SIGred/cve-2020-1350_with_tcp_handshake.pcap",
]

# TODO
# corelight/hassh
# corelight/http-more-files-names
# corelight/zeek-xor-exe-plugin
# cybera/zeek-sniffpass

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
    pcap_hash_map,
):
    assert all([pcap_hash_map.get(x, None) for x in mmguero.GetIterable(UPLOAD_ARTIFACTS)])

    response = requests.post(
        f"{malcolm_url}/mapi/agg/rule.category",
        headers={"Content-Type": "application/json"},
        json={
            "from": "2000 years ago",
            "filter": {
                "event.provider": "zeek",
                "event.dataset": "notice",
                "tags": [pcap_hash_map[x] for x in mmguero.GetIterable(UPLOAD_ARTIFACTS)],
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
