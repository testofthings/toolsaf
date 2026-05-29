from toolsaf.main import TLS
from toolsaf.common.verdict import Verdict
from toolsaf.common.basics import HostType, ExternalActivity, Status
from toolsaf.core.serializer.model_serializer import SystemSerializer
from toolsaf.builder_backend import SystemBackend, HostBackend

SERIALIZED_SYSTEM = {
    "long_name": "Test System",
    "name": "Test System",
    "description": "desc",
    "match_priority": 0,
    "address": "",
    "host_type": HostType.GENERIC.value,
    "status": "Expected",
    "verdict": Verdict.INCON.value,
    "external_activity": ExternalActivity.BANNED.value,
    "properties": {},
    "type": "system",
    "upload_tag": "test-tag",
    "ignore_rules": {"rules": {}}
}
SERIALIZED_HOST = {
    "long_name": "Device 1",
    "name": "Device 1",
    "description": "Internet Of Things device",
    "match_priority": 10,
    "address": "Device_1",
    "host_type": HostType.DEVICE.value,
    "status": Status.UNEXPECTED.value,
    "verdict": Verdict.INCON.value,
    "external_activity": ExternalActivity.PASSIVE.value,
    "properties": {},
    "addresses": ["Device_1"],
    "parent_address": "",
    "any_host": False,
    "type": "host",
    "ignore_name_requests": []
}


def test_edit_deserialized_iot_system():
    deserialized = SystemSerializer().deserialize(SERIALIZED_SYSTEM)
    assert deserialized.name == "Test System"

    sb = SystemBackend.from_entity(deserialized)
    assert len(sb._changes) == 0
    assert sb.system.name == "Test System"

    sb.device()
    assert len(sb._changes) == 1


def test_edit_deserialized_host():
    serialized = SystemSerializer()
    system = serialized.deserialize(SERIALIZED_SYSTEM)
    host = serialized.deserialize(SERIALIZED_HOST)

    system = SystemBackend.from_entity(system)
    host = HostBackend.from_entity(host, system)
    assert len(system._changes) == 0
    host / TLS
    assert len(system._changes) == 1
    pass

