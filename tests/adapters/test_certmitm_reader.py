import io
import zipfile

from tdsaf.adapters.certmitm_reader import CertMITMReader
from tdsaf.common.traffic import EvidenceSource
from tdsaf.main import TLS
from tdsaf.common.property import Properties
from tdsaf.common.verdict import Verdict
from tests.test_model import Setup


json_str = '{"client": "1.2.3.4","destination": { "ip": "10.10.10.10","port": 443}}\n{"client": "1.2.3.4","destination": { "ip": "11.11.11.11","port": 444}}'.encode("utf-8")
json_str2 = '{"client": "5.6.7.8","destination": { "ip": "12.12.12.12","port": 443}}'.encode("utf-8")

def test_process_file():
    zip_buffer = io.BytesIO()

    with zipfile.ZipFile(zip_buffer, "a", zipfile.ZIP_DEFLATED, False) as zip_file:
        for file_name, data in ([
                                ("1.2.3.4/data/data.txt", io.BytesIO(b'test')),
                                ("1.2.3.4/errors.txt", io.BytesIO(json_str)),
                                ("5.6.7.8/errors.txt", io.BytesIO(json_str2))]):
            zip_file.writestr(file_name, data.getvalue())

    setup = Setup()
    system = setup.system

    device_1 = system.backend("D1").ip("1.2.3.4")
    device_2 = system.backend("D2").ip("5.6.7.8")
    backend_1 = system.backend("BE1").ip("10.10.10.10")
    backend_2 = system.backend("BE2").ip("11.11.11.11")
    backend_3 = system.backend("BE3").ip("12.12.12.12")

    device_1 >> backend_1 / TLS             # Should fail
    device_1 >> backend_2 / TLS(port=444)   # Should fail
    device_1 >> backend_3 / TLS
    device_2 >> backend_3 / TLS             # Should fail

    reader = CertMITMReader(system)
    source = EvidenceSource(name="")
    reader.process_file(zip_buffer, "", setup.get_inspector(), source)

    assert len(system.system.get_connections()) == 4

    expected_sources = ["D1"]*3 + ["D2"]
    expected_targets = ["BE1", "BE2", "BE3", "BE3"]
    for i, conn in enumerate(system.system.get_connections()):
        assert conn.source.name == expected_sources[i] and conn.target.parent.name == expected_targets[i]
        if conn.source.name == "D1" and conn.target.parent.name == "BE3":
            # No fail
            assert len(conn.properties) == 0
        else:
            assert conn.properties[Properties.MITM].verdict == Verdict.FAIL
