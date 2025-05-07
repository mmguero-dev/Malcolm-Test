import pytest
import mmguero
import requests
import logging

LOGGER = logging.getLogger(__name__)

# You'll notice I don't use all the PCAPs in pcap/protocols here: I've opted to use some
#   other PCAPs also in the repository which trigger the same parsers but which are smaller
#   and thus faster to process.
UPLOAD_ARTIFACTS = [
    "pcap/other/Digital Bond S4/Advantech.pcap",
    "pcap/other/Digital Bond S4/BACnet_FIU.pcap",
    "pcap/other/Digital Bond S4/BACnet_Host.pcap",
    "pcap/other/Digital Bond S4/iFix_Client86.pcap",
    "pcap/other/Digital Bond S4/iFix_Server119.pcap",
    "pcap/other/Digital Bond S4/MicroLogix56.pcap",
    "pcap/other/Digital Bond S4/Modicon.pcap",
    "pcap/other/Digital Bond S4/WinXP.pcap",
    "pcap/protocols/BACnet_device_control.pcap",
    "pcap/protocols/BSAP.pcap",
    "pcap/protocols/DNP3.pcap",
    "pcap/protocols/ENIP.pcap",
    "pcap/protocols/ETHERCAT.pcap",
    "pcap/protocols/GENISYS.pcap",
    "pcap/protocols/HARTIP.pcap",
    "pcap/protocols/Modbus.pcap",
    "pcap/protocols/MQTT.pcap",
    "pcap/protocols/OmronFINS.pcap",
    "pcap/protocols/OPCUA-Binary.pcap",
    "pcap/protocols/PROFINET.pcap",
    "pcap/protocols/ROCPlus.pcap",
    "pcap/protocols/S7comm.pcap",
    "pcap/protocols/Synchrophasor.pcap",
    "pcap/protocols/TDS.pcap",
]

# TODO:
# "ecat_arp_info",
# "ecat_foe_info",
# "ecat_soe_info",
# "ge_srtp",
# "genisys",
EXPECTED_DATASETS = [
    "bacnet",
    "bacnet_discovery",
    "bacnet_device_control",
    "bacnet_property",
    "bestguess",
    "bsap_ip_header",
    "bsap_ip_rdb",
    "bsap_serial_header",
    "bsap_serial_rdb",
    "cip",
    "cip_identity",
    "cip_io",
    "cotp",
    "dnp3",
    "dnp3_control",
    "dnp3_objects",
    "ecat_aoe_info",
    "ecat_coe_info",
    "ecat_dev_info",
    "ecat_log_address",
    "ecat_registers",
    "enip",
    "hart_ip",
    "hart_ip_common_commands",
    "hart_ip_direct_pdu_command",
    "hart_ip_session_record",
    "hart_ip_universal_commands",
    "known_modbus",
    "modbus",
    "modbus_detailed",
    "modbus_mask_write_register",
    "modbus_read_device_identification",
    "modbus_read_write_multiple_registers",
    "mqtt_connect",
    "mqtt_publish",
    "mqtt_subscribe",
    "omron_fins",
    "omron_fins_data_link_status_read",
    "omron_fins_detail",
    "omron_fins_error",
    "omron_fins_file",
    "omron_fins_network_status_read",
    "opcua_binary",
    "opcua_binary_activate_session",
    "opcua_binary_activate_session_locale_id",
    "opcua_binary_browse",
    "opcua_binary_browse_description",
    "opcua_binary_browse_request_continuation_point",
    "opcua_binary_browse_response_references",
    "opcua_binary_browse_result",
    "opcua_binary_close_session",
    "opcua_binary_create_monitored_items",
    "opcua_binary_create_monitored_items_create_item",
    "opcua_binary_create_session",
    "opcua_binary_create_session_discovery",
    "opcua_binary_create_session_endpoints",
    "opcua_binary_create_session_user_token",
    "opcua_binary_create_subscription",
    "opcua_binary_diag_info_detail",
    "opcua_binary_get_endpoints",
    "opcua_binary_get_endpoints_description",
    "opcua_binary_get_endpoints_discovery",
    "opcua_binary_get_endpoints_locale_id",
    "opcua_binary_get_endpoints_profile_uri",
    "opcua_binary_get_endpoints_user_token",
    "opcua_binary_opensecure_channel",
    "opcua_binary_read",
    "opcua_binary_read_nodes_to_read",
    "opcua_binary_read_results",
    "opcua_binary_status_code_detail",
    "opcua_binary_variant_array_dims",
    "opcua_binary_variant_data",
    "opcua_binary_variant_data_value",
    "opcua_binary_variant_extension_object",
    "opcua_binary_variant_metadata",
    "opcua_binary_write",
    "profinet",
    "profinet_io_cm",
    "roc_plus",
    "roc_plus_configurable_opcode",
    "roc_plus_data_request",
    "roc_plus_file_transfer",
    "roc_plus_historical_min_max_vals",
    "roc_plus_history_information",
    "roc_plus_history_point_data",
    "roc_plus_login",
    "roc_plus_realtime_clock",
    "roc_plus_single_point_parameters",
    "roc_plus_store_and_forward",
    "roc_plus_sys_cfg",
    "roc_plus_time_period_history_points",
    "roc_plus_transaction_history",
    "roc_plus_user_defined_info",
    "s7comm",
    "s7comm_plus",
    "s7comm_read_szl",
    "s7comm_upload_download",
    "synchrophasor",
    "synchrophasor_cfg",
    "synchrophasor_cmd",
    "synchrophasor_hdr",
    "tds",
    "tds_rpc",
    "tds_sql_batch",
]


@pytest.mark.ics
@pytest.mark.mapi
@pytest.mark.pcap
def test_ot_protocols(
    malcolm_http_auth,
    malcolm_url,
    artifact_hash_map,
):
    """test_ot_protocols

    Checks for the existence of various Zeek logs (event.dataset) related to ICS/OT protocols

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


@pytest.mark.ics
@pytest.mark.mapi
@pytest.mark.pcap
def test_ics_best_guess(
    malcolm_http_auth,
    malcolm_url,
    artifact_hash_map,
):
    """test_ics_best_guess

    Check that the zeek.bestguess.* fields are generated

    Args:
        malcolm_http_auth (HTTPBasicAuth): username and password for the Malcolm instance
        malcolm_url (str): URL for connecting to the Malcolm instance
        artifact_hash_map (defaultdict(lambda: None)): a map of artifact files' full path to their file hash
    """
    for field in [
        "zeek.bestguess.category",
        "zeek.bestguess.name",
    ]:
        response = requests.post(
            f"{malcolm_url}/mapi/agg/{field}",
            headers={"Content-Type": "application/json"},
            json={
                "from": "0",
                "filter": {
                    f"!{field}": None,
                    "tags": [artifact_hash_map[x] for x in mmguero.GetIterable(UPLOAD_ARTIFACTS)],
                },
            },
            allow_redirects=True,
            auth=malcolm_http_auth,
            verify=False,
        )
        response.raise_for_status()
        buckets = {item['key']: item['doc_count'] for item in mmguero.DeepGet(response.json(), [field, 'buckets'], [])}
        LOGGER.debug(buckets)
        assert buckets
