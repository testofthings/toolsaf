import pytest
from pydantic import ValidationError

from toolsaf.common.address import Protocol
from toolsaf.common.verdict import Verdict
from toolsaf.core.serializer.event_serializer import (
    EvidenceSourceDTO, AddressMapEntryDTO, BaseEventDTO,
    EthernetFlowDTO, IPFlowDTO, BLEAdvertisementFlowDTO,
    ServiceScanDTO, HostScanDTO, PropertyAddressEventDTO,
    PropertyEventDTO, NameEventDTO, ReleaseInfoDTO, PropEventValueDTO
)


def _validate(valid_data, key_values, dto_class):
    for key, value in key_values:
        with pytest.raises(ValidationError):
            dto_class(**{**valid_data, key: value})


def _valid_evidence_source():
    return {
        "id": "id1",
        "name": "Test Source",
        "tool_label": "test-tool",
    }


def test_evidence_source_dto_invalid_values():
    key_values = [
        ("id", "id"),
        ("id", "id" + "1" * 19),
        ("id", "abc1"),
        ("id", "idabc"),
        ("id", 123),
        ("name", ""),
        ("name", "a" * 101),
        ("name", 123),
        ("tool_label", ""),
        ("tool_label", "a" * 101),
        ("tool_label", 123),
        ("target", "a" * 201),
        ("description", "a" * 4001),
        ("description", 123),
        ("location", "a" * 201),
        ("base_ref", "a" * 301),
        ("timestamp", "not-a-date"),
        ("address_map", "abc"),
        ("address_map", [123]),
    ]
    _validate(_valid_evidence_source(), key_values, EvidenceSourceDTO)


def _valid_address_map_entry():
    return {
        "address": "aa:bb:cc:dd:ee:ff",
        "entity": "Node",
    }


def test_address_map_entry_dto_invalid_values():
    key_values = [
        ("address", 123),
        ("entity", "Node/fake_proto:80"),
        ("entity", "Node/tcp:abc"),
        ("entity", 123),
    ]
    _validate(_valid_address_map_entry(), key_values, AddressMapEntryDTO)


def _valid_base_event():
    return {
        "source_id": "id1",
    }


def test_base_event_dto_invalid_values():
    key_values = [
        ("source_id", "id"),
        ("source_id", "id" + "1" * 19),
        ("source_id", "abc1"),
        ("source_id", "idabc"),
        ("source_id", 123),
        ("tail_ref", "abc"),
        ("tail_ref", ":abc"),
        ("tail_ref", ":"),
        ("tail_ref", ":" + "1" * 20),
    ]
    _validate(_valid_base_event(), key_values, BaseEventDTO)


def _valid_ethernet_flow():
    return {
        "source_id": "id1",
        "type": "ethernet-flow",
        "source": "aa:bb:cc:dd:ee:ff",
        "target": "11:22:33:44:55:66",
        "payload": 100,
        "protocol": Protocol.ETHERNET.value,
    }


def test_ethernet_flow_dto_invalid_values():
    key_values = [
        ("type", "ip-flow"),
        ("source", "not-a-hw-addr"),
        ("source", 123),
        ("target", "not-a-hw-addr"),
        ("target", 123),
        ("payload", "abc"),
        ("protocol", "unknown"),
        ("protocol", 123),
        ("timestamp", "not-a-date"),
        ("source_id", "idabc"),
        ("tail_ref", ":abc"),
    ]
    _validate(_valid_ethernet_flow(), key_values, EthernetFlowDTO)


def _valid_ip_flow():
    return {
        "source_id": "id1",
        "type": "ip-flow",
        "source": ["aa:bb:cc:dd:ee:ff", "192.168.1.1", 1234],
        "target": ["11:22:33:44:55:66", "10.0.0.1", 80],
        "protocol": Protocol.TCP.value,
    }


def test_ip_flow_dto_invalid_values():
    key_values = [
        ("type", "ethernet-flow"),
        ("source", "not-a-tuple"),
        ("source", ["not-hw", "192.168.1.1", 1234]),
        ("source", ["aa:bb:cc:dd:ee:ff", "not-ip", 1234]),
        ("target", "not-a-tuple"),
        ("target", ["not-hw", "10.0.0.1", 80]),
        ("protocol", "unknown"),
        ("timestamp", "not-a-date"),
        ("source_id", "idabc"),
    ]
    _validate(_valid_ip_flow(), key_values, IPFlowDTO)


def _valid_ble_flow():
    return {
        "source_id": "id1",
        "type": "ble-advertisement-flow",
        "source": "aa:bb:cc:dd:ee:ff",
        "event_type": 0,
        "protocol": Protocol.BLE.value,
    }


def test_ble_advertisement_flow_dto_invalid_values():
    key_values = [
        ("type", "ethernet-flow"),
        ("source", "not-a-hw-addr"),
        ("source", 123),
        ("event_type", "abc"),
        ("protocol", "unknown"),
        ("timestamp", "not-a-date"),
        ("source_id", "idabc"),
    ]
    _validate(_valid_ble_flow(), key_values, BLEAdvertisementFlowDTO)


def _valid_service_scan():
    return {
        "source_id": "id1",
        "type": "service-scan",
        "service_name": "http",
        "address": "192.168.1.1/tcp:80",
    }


def test_service_scan_dto_invalid_values():
    key_values = [
        ("type", "host-scan"),
        ("service_name", ""),
        ("service_name", "a" * 201),
        ("service_name", 123),
        ("address", 123),
        ("source_id", "idabc"),
        ("tail_ref", ":abc"),
    ]
    _validate(_valid_service_scan(), key_values, ServiceScanDTO)


def _valid_host_scan():
    return {
        "source_id": "id1",
        "type": "host-scan",
        "host": "192.168.1.1",
        "endpoints": ["192.168.1.1/tcp:80"],
    }


def test_host_scan_dto_invalid_values():
    key_values = [
        ("type", "service-scan"),
        ("host", 123),
        ("endpoints", "abc"),
        ("endpoints", [123]),
        ("source_id", "idabc"),
        ("tail_ref", ":abc"),
    ]
    _validate(_valid_host_scan(), key_values, HostScanDTO)


def _valid_prop_event_value():
    return {
        "verdict": Verdict.PASS.value,
    }


def _valid_property_address_event():
    return {
        "source_id": "id1",
        "type": "property-address-event",
        "address": "192.168.1.1",
        "key": "check:vunlz",
        "value": _valid_prop_event_value(),
    }


def test_property_address_event_dto_invalid_values():
    key_values = [
        ("type", "property-event"),
        ("address", 123),
        ("key", 123),
        ("value", {"verdict": Verdict.PASS.value, "extra_field": "x"}),
        ("source_id", "idabc"),
    ]
    _validate(_valid_property_address_event(), key_values, PropertyAddressEventDTO)


def _valid_property_event():
    return {
        "source_id": "id1",
        "type": "property-event",
        "address": "Node",
        "key": "check:vunlz",
        "value": _valid_prop_event_value(),
    }


def test_property_event_dto_invalid_values():
    key_values = [
        ("type", "property-address-event"),
        ("address", "Node/fake_proto:80"),
        ("address", "Node/tcp:abc"),
        ("address", 123),
        ("key", 123),
        ("value", {"verdict": Verdict.PASS.value, "extra_field": "x"}),
        ("source_id", "idabc"),
    ]
    _validate(_valid_property_event(), key_values, PropertyEventDTO)


def _valid_name_event():
    return {
        "source_id": "id1",
        "type": "name-event",
        "peers": [],
    }


def test_name_event_dto_invalid_values():
    key_values = [
        ("type", "property-event"),
        ("name", ""),
        ("name", "a" * 101),
        ("name", 123),
        ("tag", ""),
        ("tag", "a" * 101),
        ("tag", 123),
        ("service", "Node/fake_proto:80"),
        ("service", "Node/tcp:abc"),
        ("service", 123),
        ("address", 123),
        ("peers", "abc"),
        ("peers", [123]),
        ("peers", ["Node/fake_proto:80"]),
        ("timestamp", "not-a-date"),
        ("source_id", "idabc"),
    ]
    _validate(_valid_name_event(), key_values, NameEventDTO)


def _valid_release_info():
    return {
        "sw_name": "firmware",
    }


def test_release_info_dto_invalid_values():
    key_values = [
        ("sw_name", ""),
        ("sw_name", "a" * 101),
        ("sw_name", 123),
        ("interval_days", "abc"),
        ("latest_release_name", "a" * 101),
        ("latest_release_name", 123),
        ("first_release", "not-a-date"),
        ("latest_release", "not-a-date"),
    ]
    _validate(_valid_release_info(), key_values, ReleaseInfoDTO)


def _valid_prop_event_value_dto():
    return {
        "verdict": Verdict.PASS.value,
    }


def test_prop_event_value_dto_invalid_values():
    key_values = [
        ("verdict", "unknown"),
        ("verdict", 123),
        ("sub_keys", "abc"),
        ("sub_keys", [123]),
        ("explanation", "a" * 4001),
        ("explanation", 123),
    ]
    _validate(_valid_prop_event_value_dto(), key_values, PropEventValueDTO)
