"""Model visualization"""

from typing import List, Dict, Tuple

from tcsfw.claim_coverage import RequirementClaimMapper
from tcsfw.client_api import ClientAPI, RequestContext
from tcsfw.main import ConfigurationException
from tcsfw.model import NetworkNode, Connection, Host
from tcsfw.registry import Registry


class Visualizer:
    """Visualize system"""
    def __init__(self):
        self.placement: List[str] = []
        self.handles: Dict[str, NetworkNode] = {}
        self.images: Dict[NetworkNode, Tuple[str, int]] = {}
        self.coordinates: Dict[NetworkNode, Tuple[float, float]] = {}
        self.dimensions = 0, 0
        self.top_line = []
        self.bot_line = []

    def place(self, entity: NetworkNode) -> Tuple[int, int]:
        """Place an entity"""
        if self.dimensions[0] == 0:
            self._resolve_coordinates()
        # canvas is 1000, 1000
        xy = self.coordinates.get(entity)
        if xy is None:
            # not placed earlier
            line = self.bot_line if entity.is_global() else self.top_line
            i = len(line)
            line_wid = 2
            while i >= line_wid:
                i -= line_wid
                line_wid *= 2
            x = self.dimensions[0] / (line_wid + 1) * (i + 1)
            y = 1 if line is self.top_line else (self.dimensions[1] - 1)
            line.append(entity)
            xy = x, y
            self.coordinates[entity] = xy
        return round(xy[0] / self.dimensions[0] * 1000), round(xy[1] / self.dimensions[1] * 1000)

    def _resolve_coordinates(self):
        """Resolve planned coordinates"""
        # leave space in top and bottom for new ones
        max_x, max_y = 1, 2
        for y, line in enumerate(self.placement):
            for h, ent in self.handles.items():
                x = line.find(h)
                if x != -1:
                    if ent in self.coordinates:
                        raise ConfigurationException(f"Visual handle '{h}' has more than one entity")
                    self.coordinates[ent] = x + 1, y + 2
                    max_x, max_y = max(max_x, x + 1), max(max_y, y + 3)
        self.dimensions = max_x + 1, max_y + 1


class VisualizerAPI(ClientAPI):
    """Extend ClientAPI with coordinates and images"""
    def __init__(self, registry: Registry, claim_coverage: RequirementClaimMapper, visualizer: Visualizer):
        super().__init__(registry, claim_coverage)
        self.visualizer = visualizer

    def get_entity(self, parent: NetworkNode, context: RequestContext) -> Tuple[NetworkNode, Dict]:
        e, r = super().get_entity(parent, context)
        # Note: external hosts are listed, but without coordinates
        if not context.request.get_visual or not isinstance(e, Host) or not e.is_relevant() or not e.visual:
            return e, r
        r["xy"] = self.visualizer.place(e)
        if e in self.visualizer.images:
            r["image"] = self.visualizer.images[e]
        return e, r

    def get_connection(self, connection: Connection, context: RequestContext) -> Dict:
        r = super().get_connection(connection, context)
        # Note: external connections are listed, but without coordinates
        if not context.request.get_visual or not connection.is_relevant():
            return r
        if not (connection.source.get_parent_host().visual and connection.target.get_parent_host().visual):
            return r  # end hidden, cannot draw
        s = self.visualizer.place(connection.source.get_parent_host())
        t = self.visualizer.place(connection.target.get_parent_host())
        r["xy_line"] = [s, t] if s and t else []
        return r
