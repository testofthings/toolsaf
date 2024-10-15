"""Text tables"""

from io import StringIO
from typing import Any, Dict, List, TextIO, Tuple

from tcsfw.basics import Status
from tcsfw.entity import Entity
from tcsfw.model import Host, IoTSystem, NetworkNode, Service
from tcsfw.registry import Registry


class BaseTable:
    """Table base class"""
    def __init__(self, columns: List[Tuple[str, int]], screen_size: Tuple[int, int]):
        self.screen_size = screen_size  # (width, height or -1)
        self.columns = columns
        # spread columns evenly
        min_wid = sum(c[1] for c in columns) + len(columns) - 1
        if min_wid < screen_size[0]:
            ratio = screen_size[0] / min_wid
            self.columns = [(c[0], int(c[1] * ratio)) for c in columns]
        self.relevant_only = True
        self.include_admin = False
        self.include_external = False

    def _include(self, entity: Entity) -> bool:
        if self.relevant_only and not entity.is_relevant():
            return False
        if not self.include_external and entity.status == Status.EXTERNAL:
            return False
        if not self.include_admin and entity.is_admin():
            return False
        return True

    def print(self, stream: TextIO):
        """Print!"""
        raise NotImplementedError()

    def print_rows(self, rows: List[List[Any]], stream: TextIO) -> str:
        """Print the rows"""
        show_rows = len(rows)
        drop_rows = show_rows - self.screen_size[1] if self.screen_size[1] >= 0 else 0
        if drop_rows > 0:
            drop_rows += 1
            show_rows -= drop_rows

        screen_wid = self.screen_size[0]
        for row in rows[:show_rows]:
            line = []
            x, target_x = 0, 0
            assert len(row) == len(self.columns), f"Row and columns mismatch: {len(row)} != {len(self.columns)}"
            for i, col in enumerate(row):
                col_wid = self.columns[i][1]
                target_x += col_wid
                s = f"{col}"
                if i < len(self.columns) - 1:
                    s += ","
                    pad_len = max(0, target_x - x - len(s))
                    s = s + " " * pad_len
                line.append(s[:screen_wid - x])
                x += len(s)
                # space between columns
                target_x += 1
                x += 1
            line_s = "".join(line)
            stream.write(f"{line_s}\n")
        if drop_rows > 0:
            stream.write(f"[...{drop_rows} rows omitted]\n")

class HostTable(BaseTable):
    """Host table"""
    def __init__(self, root: IoTSystem, screen_size: Tuple[int, int]):
        super().__init__([
            ("Host", 10),
            ("Service", 20),
            ("Component", 10),
            ("Status", 10),
        ], screen_size)
        self.root = root

    def print(self, stream: TextIO):
        rows = [[h[0] for h in self.columns]]

        def _components(node: NetworkNode):
            for c in node.components:
                rows.append(['', '', c.name, c.status_string()])

        for h in self.root.get_children():
            if isinstance(h, Host):
                if not self._include(h):
                    continue
                rows.append([h.long_name(), '', '', h.status_string()])
                _components(h)
                for s in h.get_children():
                    if not self._include(s):
                        continue
                    if isinstance(s, Service):
                        rows.append(['', s.long_name(), '', s.status_string()])
                        _components(s)

        self.print_rows(rows, stream)


class ConnectionTable(BaseTable):
    """Host table"""
    def __init__(self, root: IoTSystem, screen_size: Tuple[int, int]):
        super().__init__([
            ("Source", 20),
            ("Target", 20),
            ("Protocol", 10),
            ("Status", 10),
        ], screen_size)
        self.root = root

    def print(self, stream: TextIO):
        rows = [[h[0] for h in self.columns]]
        for c in self.root.get_connections(relevant_only=False):
            if not self._include(c):
                continue
            s, t = c.source, c.target
            proto = ""
            if isinstance(t, Service) and t.protocol is not None:
                proto = t.protocol.name
            rows.append([s.long_name(), t.long_name(), proto, c.status_string()])

        self.print_rows(rows, stream)


class SourceTable(BaseTable):
    """Source table"""
    def __init__(self, registry: Registry, screen_size: Tuple[int, int]):
        super().__init__([
            ("Source", 20),
            ("Target", 40),
            ("Label", 10),
            ("Age", 10),
        ], screen_size)
        self.registry = registry

    def print(self, stream: TextIO):
        rows = [[h[0] for h in self.columns]]
        sources = self.registry.database.get_souces()
        for src in sources:
            rows.append([src.name, src.target, src.label, ""])

        self.print_rows(rows, stream)


class TableView:
    """View of one or more tables"""
    def __init__(self, tables: List[BaseTable]) -> None:
        self.tables = tables

    @classmethod
    def get_print(cls, registry: Registry, name: str, parameters: Dict[str, str]) -> str:
        """Get printout by name"""
        screen = parameters.get("screen")
        if screen:
            screen_size = tuple(int(x) for x in screen.split("x"))
            assert len(screen_size) == 2
        else:
            screen_size = (80, 50)
        model = registry.get_system()
        if name == "system":
            screen_size = screen_size[0], int(screen_size[1] / 2)
            view = TableView([HostTable(model, screen_size), ConnectionTable(model, screen_size)])
        elif name == "sources":
            view = TableView([SourceTable(registry, screen_size)])
        else:
            raise ValueError(f"Unnown view '{name}'")
        buf = StringIO()
        view.print(buf)
        return buf.getvalue()

    def print(self, stream: TextIO):
        """Print all tables"""
        for t in self.tables:
            t.print(stream)
