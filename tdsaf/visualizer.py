"""Model visualization"""

from typing import List, Dict, Tuple, Any

from tdsaf.main import ConfigurationException
from tdsaf.core.model import NetworkNode


class Visualizer:
    """Visualize system"""
    def __init__(self) -> None:
        self.placement: Tuple[str, ...] = ()
        self.handles: Dict[str, NetworkNode] = {}
        self.images: Dict[NetworkNode, Tuple[str, int]] = {}
        self.coordinates: Dict[NetworkNode, Tuple[float, float]] = {}
        self.dimensions = 0, 0
        self.top_line: List[Any] = []
        self.bot_line: list[Any] = []

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

    def _resolve_coordinates(self) -> None:
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
