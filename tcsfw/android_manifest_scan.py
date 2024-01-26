from io import BytesIO
import pathlib
from typing import cast, List
from xml.etree import ElementTree

from tcsfw.components import Software
from tcsfw.entity import Entity
from tcsfw.event_interface import PropertyEvent, EventInterface
from tcsfw.model import IoTSystem, HostType, NodeComponent
from tcsfw.property import PropertyVerdict, Properties, PropertyKey
from tcsfw.tools import ComponentCheckTool
from tcsfw.traffic import EvidenceSource, Evidence
from tcsfw.verdict import Verdict


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

            key = PropertyVerdict("permission", name)
            val = key.get(software.properties)
            key_set.add(key)

            if self.load_baseline:
                software.permissions.add(name)
                ver = Verdict.PASS
            else:
                ver = Verdict.PASS if val else Verdict.FAIL

            if self.send_events:
                ev = PropertyEvent(evidence, software, key.value(ver))
                interface.property_update(ev)

        unseen = software.permissions - perm_set
        for name in sorted(unseen):
            # unseen permissions are failures
            if self.send_events:
                key = PropertyVerdict("permission", name)
                key_set.add(key)
                ev = PropertyEvent(evidence, software, key.value(Verdict.FAIL))
                interface.property_update(ev)

        if self.send_events:
            ev = PropertyEvent(evidence, software, Properties.PERMISSIONS.value(key_set, self.tool.name))
            interface.property_update(ev)

    def _entity_coverage(self, entity: Entity) -> List[PropertyKey]:
        if isinstance(entity, Software) and entity.get_host().host_type == HostType.MOBILE:
            return [Properties.PERMISSIONS]
        return []
