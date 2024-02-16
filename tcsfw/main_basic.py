from typing import Dict, Optional, Self, List

from tcsfw.address import AnyAddress, HWAddress, IPAddress
from tcsfw.batch_import import LabelFilter
from tcsfw.claim_coverage import RequirementClaimMapper
from tcsfw.components import Software
from tcsfw.model import ExternalActivity, EvidenceNetworkSource, Addressable, IoTSystem, Host
from tcsfw.registry import Registry


class BuilderInterface:
    """Abstract builder interface"""
    pass


class SystemInterface(BuilderInterface):
    """System root builder interface"""
    def __init__(self, name: str):
        self.system = IoTSystem(name)


class NodeInterface(BuilderInterface):
    """Node building interface"""
    def __init__(self, entity: Addressable, system: SystemInterface):
        self.entity = entity
        self.system = system

    def get_software(self) -> Software:
        raise NotImplementedError()


class HostInterface(NodeInterface):
    def __init__(self, entity: Host, system: SystemInterface):
        super().__init__(entity, system)
        self.entity = entity


class SoftwareInterface:
    """Software building interface"""
    def get_software(self) -> Software:
        raise NotImplementedError()


class SubLoader:
    """Base class for loaders"""
    def __init__(self, name: str):
        self.loader_name = name
        self.base_ref = ""
        self.mappings: Dict[AnyAddress, NodeInterface] = {}
        self.activity_map: Dict[NodeInterface, ExternalActivity] = {}
        self.parent_loader: Optional[SubLoader] = None
        self.source_label = "?"
        self.baseline = False  # read a baseline, only supported for some loaders

    def hw(self, entity: NodeInterface, *hw_address: str) -> Self:
        for a in hw_address:
            self.mappings[HWAddress.new(a)] = entity
        return self

    def ip(self, entity: NodeInterface, *ip_address: str) -> Self:
        for a in ip_address:
            self.mappings[IPAddress.new(a)] = entity
        return self

    def external_activity(self, entity: NodeInterface, activity: ExternalActivity) -> Self:
        self.activity_map[entity] = activity
        return self

    def get_source(self) -> EvidenceNetworkSource:
        add_map = {}
        ext_map = {}
        if self.parent_loader:
            ps = self.parent_loader.get_source()
            add_map.update(ps.address_map)
            ext_map.update(ps.activity_map)
        add_map.update({a: e.entity for a, e in self.mappings.items()})
        ext_map.update({e.entity: fs for e, fs in self.activity_map.items()})
        return EvidenceNetworkSource(self.loader_name, self.base_ref, self.source_label, address_map=add_map,
                                     activity_map=ext_map)

    def load(self, registry: Registry, coverage: RequirementClaimMapper, filter: LabelFilter):
        """Load evidence"""
        pass
