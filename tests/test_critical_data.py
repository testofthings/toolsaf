from tcsfw.components import StoredData
from tcsfw.selector import Finder
from tests.test_model import Setup


def test_data_placement():
    su = Setup()
    data = su.system.data(["data-a"])

    # data in default location
    refs = StoredData.find_data(su.system.system).sub_components
    assert [r.data for r in refs] == data.data

    dev = su.system.device()
    dev.use_data(data)

    # data moved from default location
    assert StoredData.find_data(su.system.system).sub_components == []
    refs = StoredData.find_data(dev.entity).sub_components
    assert [r.data for r in refs] == data.data


def test_data_finding():
    su = Setup()
    data = su.system.data(["data-a"])

    refs = StoredData.find_data(su.system.system).sub_components
    js = Finder.specify(refs[0])
    assert js == {
        "system": True,
        "data": "data-a",
    }

    rr = Finder.find(su.system.system, js)
    assert rr.data == data.data[0]
