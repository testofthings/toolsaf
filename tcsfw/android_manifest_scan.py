from io import BytesIO
import pathlib
from typing import cast, List
from xml.etree import ElementTree

from tcsfw.components import Software
from tcsfw.entity import Entity
from tcsfw.event_interface import PropertyEvent, EventInterface
from tcsfw.model import IoTSystem, NodeComponent
from tcsfw.property import Properties, PropertyKey
from tcsfw.tools import ComponentCheckTool
from tcsfw.traffic import EvidenceSource, Evidence
from tcsfw.basics import HostType, Verdict


class AndroidManifestScan(ComponentCheckTool):
    def __init__(self, system: IoTSystem):
        super().__init__("android", ".xml", system)
        self.tool.name = "Android Manifest"

    def _filter_component(self, component: NodeComponent) -> bool:
        return isinstance(component, Software)

    def process_stream(self, component: NodeComponent, data_file: BytesIO, interface: EventInterface,
                       source: EvidenceSource):
        software = cast(Software, component)

        evidence = Evidence(source)

        tree = ElementTree.parse(data_file)
        perm_set = set()
        key_set = set()
        for uses_p in tree.getroot().iter('uses-permission'):
            name = uses_p.attrib.get("{http://schemas.android.com/apk/res/android}name")
            if "." in name:
                name = name[name.rindex(".") + 1:]
            perm_set.add(name)

            key = PropertyKey("permission", name)
            val = key.get(software.properties)
            key_set.add(key)

            if self.load_baseline:
                software.permissions.add(name)
                ver = Verdict.PASS
            else:
                ver = Verdict.PASS if val else Verdict.FAIL

            if self.send_events:
                ev = PropertyEvent(evidence, software, key.verdict(ver))
                interface.property_update(ev)

        unseen = software.permissions - perm_set
        for name in sorted(unseen):
            # unseen permissions are failures
            if self.send_events:
                key = PropertyKey("permission", name)
                key_set.add(key)
                ev = PropertyEvent(evidence, software, key.verdict(Verdict.FAIL))
                interface.property_update(ev)

        if self.send_events:
            ev = PropertyEvent(evidence, software, Properties.PERMISSIONS.value_set(key_set, self.tool.name))
            interface.property_update(ev)
