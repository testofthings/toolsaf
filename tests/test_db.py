import tempfile
from tcsfw.address import HWAddress, IPAddress
from tcsfw.basics import ExternalActivity
from tcsfw.builder_backend import SystemBackend
from tcsfw.event_interface import PropertyEvent
from tcsfw.model import EvidenceNetworkSource
from tcsfw.property import Properties
from tcsfw.registry import Registry, Inspector
from tcsfw.sql_database import SQLDatabase
from tcsfw.traffic import NO_EVIDENCE, Evidence, EvidenceSource, IPFlow


def test_db_id_storage():
    """Test storing and retrieving entity IDs from SQL database"""

    with tempfile.NamedTemporaryFile() as tmp_file:
        tmp = tmp_file.name

        # Run 1
        sb = SystemBackend()
        dev1 = sb.device()
        reg = Registry(Inspector(sb.system), db=SQLDatabase(f"sqlite:///{tmp}")).finish_model_load()
        assert reg.get_id(dev1.entity) == 2

        # Run 2
        sb = SystemBackend()
        dev2 = sb.device("Device two")
        reg = Registry(Inspector(sb.system), db=SQLDatabase(f"sqlite:///{tmp}")).finish_model_load()
        assert reg.get_id(dev2.entity) == 3

        # Run 3
        sb = SystemBackend()
        dev3 = sb.device("Device three")
        reg = Registry(Inspector(sb.system), db=SQLDatabase(f"sqlite:///{tmp}")).finish_model_load()
        assert reg.get_id(dev1.entity) == 2
        assert reg.get_id(dev3.entity) == 4
        assert reg.get_id(dev2.entity) == 3


def test_with_unepxected_entities():
    """Test DB with unexpected entities created as due events, not originally in the model"""
    with tempfile.NamedTemporaryFile() as tmp_file:
        tmp = tmp_file.name

        # Run 1
        sb = SystemBackend()
        dev1 = sb.device().hw("1:0:0:0:0:1")
        reg = Registry(Inspector(sb.system), db=SQLDatabase(f"sqlite:///{tmp}")).finish_model_load()
        # connection, target is new unexpected entity
        p = IPFlow.UDP("1:0:0:0:0:1", "192.168.0.1", 1100) >> ("1:0:0:0:0:2", "192.168.0.2", 1234)
        con = reg.connection(p)
        # send property event to new entity
        ev = PropertyEvent(NO_EVIDENCE, con.target, Properties.AUTHENTICATION.verdict())
        reg.property_update(ev)
        # it is no there - events no longer delivered to unexpected entities
        assert Properties.AUTHENTICATION not in con.target.properties

        # in the next run, the property event goes to entity now in the model

        # Run 2
        sb = SystemBackend()
        dev1 = sb.device().hw("1:0:0:0:0:1")
        reg = Registry(Inspector(sb.system), db=SQLDatabase(f"sqlite:///{tmp}")).finish_model_load()


def test_db_source_storage():
    """Test storing and restoring evidence sources"""
    with tempfile.NamedTemporaryFile() as tmp_file:
        tmp = tmp_file.name

        sb = SystemBackend()
        dev1 = sb.device()
        reg = Registry(Inspector(sb.system), db=SQLDatabase(f"sqlite:///{tmp}")).finish_model_load()

        src = EvidenceNetworkSource("Source A")
        src.address_map[HWAddress.new("1:0:0:0:0:1")] = dev1.entity
        src.activity_map[dev1.entity] = ExternalActivity.BANNED  # the default, but practising
        p = IPFlow.UDP("1:0:0:0:0:1", "192.168.0.1", 1100) >> ("1:0:0:0:0:2", "192.168.0.2", 1234)
        p.evidence = Evidence(src)
        assert dev1.entity.connections == []
        con = reg.connection(p)
        assert dev1.entity.connections[0] == con  # thanks to address mapping

        sb = SystemBackend()
        dev1 = sb.device()
        reg = Registry(Inspector(sb.system), db=SQLDatabase(f"sqlite:///{tmp}"))
        assert dev1.entity.connections == []
        reg.finish_model_load()
        assert dev1.entity.connections[0].source == dev1.entity  # thanks to address mapping
