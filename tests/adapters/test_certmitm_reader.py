import io
import zipfile

from toolsaf.adapters.certmitm_reader import CertMITMReader
from toolsaf.common.traffic import EvidenceSource
from toolsaf.main import TLS
from toolsaf.common.property import Properties, PropertyKey
from toolsaf.common.verdict import Verdict
from tests.test_model import Setup


json_str =  '{"client": "1.2.3.4","destination": {"ip": "10.10.10.10","port": 443, "name": "BE1.com"}}\n{"client": "1.2.3.4","destination": { "ip": "11.11.11.11","port": 444, "name": "BE2.com"}}'.encode("utf-8")
json_str2 = '{"client": "5.6.7.8","destination": {"ip": "12.12.12.12","port": 443, "name": "BE3.com"}}'.encode("utf-8")

def test_process_file():
    zip_buffer = io.BytesIO()

    with zipfile.ZipFile(zip_buffer, "a", zipfile.ZIP_DEFLATED, False) as zip_file:
        for file_name, data in ([
                                ("1.2.3.4/data/data.txt", io.BytesIO(b'test')),
                                ("1.2.3.4/errors.txt", io.BytesIO(json_str)),
                                ("5.6.7.8/errors.txt", io.BytesIO(json_str2)),
                                ("certificates/BE1.com", io.BytesIO(b'test')),
                                ("certificates/BE2.com", io.BytesIO(b'test')),
                                ("certificates/BE3.com", io.BytesIO(b'test'))]):
            zip_file.writestr(file_name, data.getvalue())

    setup = Setup()
    system = setup.system

    device_1 = system.backend("D1").ip("1.2.3.4")
    device_2 = system.backend("D2").ip("5.6.7.8")
    backend_1 = system.backend("BE1").ip("10.10.10.10").dns("BE1.com")
    backend_2 = system.backend("BE2").ip("11.11.11.11").dns("BE2.com")
    backend_3 = system.backend("BE3").ip("12.12.12.12").dns("BE3.com")

    device_1 >> backend_1 / TLS             # Should fail
    device_1 >> backend_2 / TLS(port=444)   # Should fail
    device_1 >> backend_3 / TLS             # Should pass
    device_2 >> backend_3 / TLS             # Should fail

    reader = CertMITMReader(setup.get_system())
    source = EvidenceSource(name="")
    reader.process_file(zip_buffer, "", setup.get_inspector(), source)

    assert len(system.system.get_connections()) == 4

    expected_sources = ["D1"]*3 + ["D2"]
    expected_targets = ["BE1", "BE2", "BE3", "BE3"]
    for i, conn in enumerate(system.system.get_connections()):
        assert conn.source.name == expected_sources[i] and conn.target.parent.name == expected_targets[i]
        if conn.source.name == "D1" and conn.target.parent.name == "BE3":
            # No fail
            assert conn.properties[PropertyKey("certmitm")].verdict == Verdict.PASS
        else:
            assert conn.properties[PropertyKey("certmitm")].verdict == Verdict.FAIL

