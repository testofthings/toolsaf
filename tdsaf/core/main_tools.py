"""Tool loader definitions"""

from typing import Any, List, Dict, Tuple, Self, Optional

from tdsaf.common.address import AnyAddress, HWAddress, IPAddress, Protocol
from tdsaf.common.basics import ExternalActivity
from tdsaf.adapters.batch_import import LabelFilter
from tdsaf.core.event_interface import PropertyEvent
from tdsaf.main import EvidenceBuilder, FlowBuilder, TrafficDataBuilder, NodeBuilder, SystemBuilder
from tdsaf.core.entity_selector import SelectorContext
from tdsaf.core.selector import AbstractSelector, Select
from tdsaf.core.model import Addressable, EvidenceNetworkSource
from tdsaf.common.property import PropertyKey
from tdsaf.core.registry import Registry
from tdsaf.common.traffic import NO_EVIDENCE, Evidence, Flow, IPFlow


class NodeManipulator:
    """Interface to interact with other backend"""
    def get_node(self) -> Addressable:
        """Get manipulated addressable node"""
        raise NotImplementedError()


class SubLoader:
    """Base class for direct evidence/claim loaders"""
    def __init__(self, name: str) -> None:
        self.loader_name = name
        self.base_ref = ""
        self.mappings: Dict[AnyAddress, NodeManipulator] = {}
        self.activity_map: Dict[NodeManipulator, ExternalActivity] = {}
        self.parent_loader: Optional[SubLoader] = None
        self.source_label = "?"
        self.baseline = False  # read a baseline, only supported for some loaders

    def hw(self, entity: NodeBuilder, *hw_address: str) -> Self:
        """Map data-specific hardware address to entity"""
        assert isinstance(entity, NodeManipulator)
        for a in hw_address:
            self.mappings[HWAddress.new(a)] = entity
        return self

    def ip(self, entity: NodeBuilder, *ip_address: str) -> Self:
        """Map data-specific IP address to entity"""
        assert isinstance(entity, NodeManipulator)
        for a in ip_address:
            self.mappings[IPAddress.new(a)] = entity
        return self

    def external_activity(self, entity: NodeBuilder, activity: ExternalActivity) -> Self:
        """Map data-specific external activity to entity"""
        assert isinstance(entity, NodeManipulator)
        self.activity_map[entity] = activity
        return self

    def get_source(self) -> EvidenceNetworkSource:
        """Get the evidence source configured for this loader"""
        add_map = {}
        ext_map = {}
        if self.parent_loader:
            ps = self.parent_loader.get_source()
            add_map.update(ps.address_map)
            ext_map.update(ps.activity_map)
        add_map.update({a: e.get_node() for a, e in self.mappings.items()})
        ext_map.update({e.get_node(): fs for e, fs in self.activity_map.items()})
        s = EvidenceNetworkSource(self.loader_name, self.base_ref, self.source_label, address_map=add_map,
                                  activity_map=ext_map)
        s.model_override = True
        return s

    def load(self, registry: Registry, label_filter: LabelFilter) -> None:
        """Load evidence"""


class EvidenceLoader(EvidenceBuilder):
    """Load evidence files"""
    def __init__(self, builder: SystemBuilder) -> None:
        super().__init__()
        self.builder = builder
        self.subs: List[SubLoader] = []

    def traffic(self, label: str="Fab data") -> 'FabricationLoader':
        """Fabricate evidence for testing or visualization"""
        sl = FabricationLoader(label)
        self.subs.append(sl)
        return sl

    @classmethod
    def group(cls, group_label: str, *tools: 'ToolPlanLoader') -> None:
        """Create a group of tools"""
        for t in tools:
            # t.load_label = group_label  # label in source filtering
            t.groups.append(group_label)


class FabricationLoader(SubLoader, TrafficDataBuilder):
    """Fabricate evidence for testing or visualization"""
    def __init__(self, source_label: str) -> None:
        super().__init__(source_label)
        self.flows: List[Flow] = []

    def connection(self, flow: FlowBuilder) -> Self:
        """Add a connection"""
        # NOTE: Only UDP and TCP are implemented at this point
        f = IPFlow(NO_EVIDENCE, flow.source, flow.target, Protocol.get_protocol(flow.protocol))
        self.flows.append(f)
        return self

    def load(self, registry: Registry, label_filter: LabelFilter) -> None:
        if not label_filter.filter(self.source_label):
            return
        evi = Evidence(self.get_source())
        for f in self.flows:
            f.evidence = evi  # override evidence
            registry.connection(f)


class ToolPlanLoader(SubLoader):
    """Load plans for future tools"""
    def __init__(self, group: Tuple[str, str]) -> None:
        super().__init__(group[1])    # group[0] is e.g. 'basic-tools', 'advanced-tools', 'custom-tools'
        self.source_label = group[1]  # group[1] is fancy names for them (just captialize?)
        self.location: AbstractSelector = Select.system()
        self.properties: Dict[PropertyKey, Any] = {}
        self.groups = ["planning", group[0]]

    def load(self, registry: Registry, label_filter: LabelFilter) -> None:
        for g in self.groups:
            if g in label_filter.excluded:
                return  # explicitly excluded
            if g in label_filter.included:
                break  # explicitly included
        else:
            return  # plans must be explicitly included

        evidence = Evidence(self.get_source())
        for p, v in self.properties.items():
            entities = self.location.select(registry.get_system(), SelectorContext())
            for ent in entities:
                ev = PropertyEvent(evidence, ent, (p, v))
                registry.property_update(ev)
