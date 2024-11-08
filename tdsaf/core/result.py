"""Simple text report on the system status"""

import logging
from typing import TextIO, List, Dict

from tdsaf.common.basics import ConnectionType
from tdsaf.common.entity import Entity
from tdsaf.core.model import Host, Service, NetworkNode
from tdsaf.common.property import Properties, PropertyKey
from tdsaf.core.registry import Registry

# Keywords for verdicts
FAIL = "fail"
PASS = "pass"
INCONCLUSIVE = "-"


class Report:
    """Report of the system status"""
    def __init__(self, registry: Registry):
        self.registry = registry
        self.system = registry.system
        self.source_count = 3
        self.logger = logging.getLogger("reporter")

    def print_properties(self, entity: NetworkNode, indent: str, writer: TextIO):
        """Print properties from entity"""
        for k, v in entity.properties.items():
            if k == Properties.EXPECTED:
                continue  # encoded into status string
            com = k.get_explanation(v)
            com = f" # {com}" if com else ""
            writer.write(f"{indent}{k.get_value_string(v)}{com}\n")
            self._print_source(writer, entity, 2, k)

    def print_report(self, writer: TextIO):
        """Print textual report"""
        writer.write("== System ==\n")
        self.print_properties(self.system, "  ", writer)

        hosts = self.system.get_hosts()
        writer.write("== Hosts ==\n")
        rev_map: Dict[str, List[Host]] = {}
        for h in hosts:
            if not h.is_relevant():
                continue
            h_name = f"{h.name}"
            writer.write(f"{h_name} [{h.status_string()}]\n")
            self._print_source(writer, h, 1)
            ads = [f"{a}" for a in sorted(h.addresses)]
            for a in ads:
                rev_map.setdefault(a, []).append(h)
            ads = [a for a in ads if a != h_name]
            if ads:
                writer.write("  Addresses: " + " ".join(ads) + "\n")

            for comp in h.components:
                writer.write(f"  {comp.name} [Component]\n")
                sw_info = comp.info_string()
                if sw_info:
                    writer.write("    " + sw_info.replace("\n", "\n    ") + "\n")
                self._print_source(writer, comp, 2)
                self.print_properties(comp, "    ", writer)

            self.print_properties(h, "  ", writer)
            for s in h.children:
                auth = f" auth={s.authentication}" if isinstance(s, Service) else ""
                writer.write(f"  {s.name} [{s.status_string()}]{auth}\n")
                self._print_source(writer, s, 2)
                self.print_properties(s, "    ", writer)
        for ad, hs in sorted(rev_map.items()):
            if len(hs) > 1:
                self.logger.warning("DOUBLE mapped %s: %s", ad, ", ".join([f"{h}" for h in hs]))

        writer.write("== Connections ==\n")
        for conn in self.system.get_connections(relevant_only=False):
            stat = conn.con_type.value if conn.con_type == ConnectionType.LOGICAL else conn.status_string()
            writer.write(f"  {conn.source.long_name():<30} ==> {conn.target.long_name()} [{stat}]\n")
            self._print_source(writer, conn, 2)
            self.print_properties(conn, "    ", writer)

    def _print_source(self, writer: TextIO, entity: Entity, indentation: int, key: PropertyKey = Properties.EXPECTED):
        """Print source of entity"""
        if not self.source_count:
            return
        events = self.registry.logging.get_log(entity, {key})
        logged = set()
        for e in events:
            if e.event.evidence in logged:
                continue
            logged.add(e.event.evidence)
            src = e.event.evidence.get_reference()
            writer.write(f"{'  ' * indentation}@{src}\n")
            if len(logged) >= self.source_count:
                break
