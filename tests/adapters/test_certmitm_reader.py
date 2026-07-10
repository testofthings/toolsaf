import io
import zipfile

from toolsaf.adapters.certmitm_reader import CertMITMReader
from toolsaf.common.traffic import EvidenceSource
from toolsaf.main import TLS, MQTT
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
                                ("certificates/", io.BytesIO(b'')),
                                ("certificates/BE1.com", io.BytesIO(b'test')),
                                ("certificates/BE2.com", io.BytesIO(b'test')),
                                ("certificates/BE3.com", io.BytesIO(b'test')),
                                ("certificates/BE4.com", io.BytesIO(b'test')),
                                ("certificates/BE5.com", io.BytesIO(b'test')),
                                ("certificates/15.15.15.15_test.pem", io.BytesIO(b'test'))]):
            zip_file.writestr(file_name, data.getvalue())

    setup = Setup()
    system = setup.system

    device_1 = system.backend("D1").ip("1.2.3.4")
    device_2 = system.backend("D2").ip("5.6.7.8")
    backend_1 = system.backend("BE1").ip("10.10.10.10").dns("BE1.com")
    backend_2 = system.backend("BE2").ip("11.11.11.11").dns("BE2.com")
    backend_3 = system.backend("BE3").ip("12.12.12.12").dns("BE3.com")
    backend_4 = system.backend("BE4").ip("13.13.13.13").dns("BE4.com")
    backend_5 = system.backend("BE5").ip("14.14.14.14").dns("BE5.com")
    backend_6 = system.backend("BE6").ip("15.15.15.15")  # matched by IP-named certificate

    device_1 >> backend_1 / TLS                     # Should fail
    device_1 >> backend_2 / TLS(port=444)           # Should fail
    device_1 >> backend_3 / TLS                     # Should pass
    device_2 >> backend_3 / TLS                     # Should fail
    device_1 >> backend_4 / MQTT(port=8883, tls=True)  # Encrypted MQTT, should pass
    device_1 >> backend_5 / MQTT(port=1883)         # Plaintext MQTT, no verdict
    device_1 >> backend_6 / TLS                     # Cert named by IP, should pass

    reader = CertMITMReader(setup.get_system())
    source = EvidenceSource(name="")
    reader.process_file(zip_buffer, "", setup.get_inspector(), source)

    connections = system.system.get_connections()
    assert len(connections) == 7

    key = PropertyKey("certmitm")
    # Connections (by source, backend) that were tested but not intercepted -> PASS
    should_pass = {("D1", "BE3"), ("D1", "BE4"), ("D1", "BE6")}
    # Encryption unknown (plaintext) -> certmitm does not apply a verdict
    no_verdict = {("D1", "BE5")}
    for conn in connections:
        pair = (conn.source.name, conn.target.parent.name)
        if pair in no_verdict:
            assert key not in conn.properties
        elif pair in should_pass:
            assert conn.properties[key].verdict == Verdict.PASS
        else:
            assert conn.properties[key].verdict == Verdict.FAIL

