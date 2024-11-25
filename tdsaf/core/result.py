"""Simple text report on the system status"""

import sys
import logging
from typing import TextIO, List, Dict
from colored import Fore, Style

from tdsaf.common.basics import ConnectionType
from tdsaf.common.entity import Entity
from tdsaf.common.verdict import Verdict
from tdsaf.core.model import Host, NetworkNode
from tdsaf.common.property import Properties, PropertyKey
from tdsaf.core.registry import Registry


INDENT = "  "
SUB_INDENT = INDENT + "  "


class Report:
    """Report of the system status"""
    def __init__(self, registry: Registry):
        self.registry = registry
        self.system = registry.system
        self.source_count = 3
        self.show_permissions = False
        self.logger = logging.getLogger("reporter")

    def get_colored_verdict(self, verdict: str) -> str:
        """Add color to verdict string if output not redirected"""
        if verdict.lower() == "incon":
            return "[ ]"
        if sys.stdout.isatty():
            color = Fore.green if verdict.lower() == "pass" else Fore.red
            reset = Style.reset
        else:
            color, reset = "", ""
        return f"[{color}{verdict[0]}{reset}]"

    def print_properties(self, entity: NetworkNode, indent: str, writer: TextIO):
        """Print properties from entity"""
        for k, v in entity.properties.items():
            if k == Properties.EXPECTED:
                continue  # encoded into status string
            com = k.get_explanation(v)
            com = f" # {com}" if com else ""
            s = k.get_value_string(v)
            if 'permission' in s and not self.show_permissions:
                continue
            writer.write(f"{indent}{s}{com}\n")
            self._print_source(writer, entity, 2, k)

    def print_report(self, writer: TextIO):
        """Print textual report"""
        cache: Dict[Entity, Verdict] = {}
        system_verdict = Verdict.PASS

        hosts = self.system.get_hosts()
        for h in hosts:
            if h.get_verdict(cache) == Verdict.FAIL:
                system_verdict = Verdict.FAIL
        writer.write(f"{self.get_colored_verdict(system_verdict.name)} {self.system.long_name()}\n")
        self.print_properties(self.system, "  ", writer)

        writer.write("## Hosts and Services\n")
        rev_map: Dict[str, List[Host]] = {}
        for h in hosts:
            if not h.is_relevant():
                continue
            h_name = f"{h.name}"
            aggregate_verdict = h.get_verdict(cache)
            writer.write(f"{self.get_colored_verdict(aggregate_verdict.value)} {h_name}\n")
            self._print_source(writer, h, 1)
            ads = [f"{a}" for a in sorted(h.addresses)]
            for a in ads:
                rev_map.setdefault(a, []).append(h)
            ads = [a for a in ads if a != h_name]
            if ads:
                writer.write(INDENT + "Addresses: " + " ".join(ads) + "\n")

            for comp in h.components:
                writer.write(f"{INDENT}{comp.name} [Component]\n")
                sw_info = comp.info_string()
                if sw_info:
                    writer.write(SUB_INDENT + sw_info.replace("\n", "\n    ") + "\n")
                self._print_source(writer, comp, 2)
                self.print_properties(comp, SUB_INDENT, writer)

            self.print_properties(h, "  ", writer)
            for s in h.children:
                writer.write(f"{INDENT}[{s.status_string()}] {s.name}\n")
                self._print_source(writer, s, 2)
                self.print_properties(s, "    ", writer)
        for ad, hs in sorted(rev_map.items()):
            if len(hs) > 1:
                self.logger.warning("DOUBLE mapped %s: %s", ad, ", ".join([f"{h}" for h in hs]))

        writer.write("## Connections\n")
        for conn in self.system.get_connections(relevant_only=False):
            stat = conn.con_type.value if conn.con_type == ConnectionType.LOGICAL else conn.status_string()
            writer.write(f"[{stat}] {conn.source.long_name():<30} ==> {conn.target.long_name()}\n")
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
