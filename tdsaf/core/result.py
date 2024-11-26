"""Simple text report on the system status"""

import sys
import shutil
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

OUTPUT_REDIRECTED = not sys.stdout.isatty()
GREEN = Fore.green if not OUTPUT_REDIRECTED else ""
YELLOW = Fore.yellow if not OUTPUT_REDIRECTED else ""
RED = Fore.red if not OUTPUT_REDIRECTED else ""
BOLD = Style.bold if not OUTPUT_REDIRECTED else ""
RESET = Style.reset if not OUTPUT_REDIRECTED else ""


class Report:
    """Report of the system status"""
    def __init__(self, registry: Registry):
        self.registry = registry
        self.system = registry.system
        self.source_count = 3
        self.show_properties = False
        self.logger = logging.getLogger("reporter")

    def get_verdict_color(self, verdict: any) -> str:
        """Returns color value for Verdict or string"""
        if isinstance(verdict, Verdict):
            return GREEN if verdict.value == Verdict.PASS else RED
        if isinstance(verdict, str):
            verdict = verdict.lower()
            if "/" in verdict:
                v = verdict.split("/")[1]
                return [RED, GREEN, YELLOW][["fail", "pass", "incon"].index(v)]
            if "pass" in verdict:
                return GREEN
            if "fail" in verdict:
                return RED
            if "incon" in verdict:
                return YELLOW
        return ""

    def get_terminal_width(self) -> int:
        """Returns terminal width or fallback value"""
        w, _ = shutil.get_terminal_size(fallback=(90, 30))
        return w

    def print_title(self, text: str, symbol: str, writer: TextIO, skip_first: bool=False) -> None:
        """Writes title sections to the output"""
        w = self.get_terminal_width()
        if not skip_first:
            writer.write(symbol * w + "\n")
        writer.write(text + "\n")
        writer.write(symbol * w + "\n")

    def get_title_text(self, verdict: any) -> str:
        """Returns the main title of the output"""
        color = self.get_verdict_color(verdict)
        if isinstance(verdict, Verdict):
            verdict = verdict.value
        return f"{'Report for:':<16} {BOLD}{self.system.long_name()}{RESET}\n" + \
                f"{color}{'Verdict:':<16} {BOLD}{verdict}{RESET}"

    def print_properties(self, entity: NetworkNode, writer: TextIO):
        """Print properties from entity"""
        if not self.show_properties:
            return
        for k, v in entity.properties.items():
            if k == Properties.EXPECTED:
                continue  # encoded into status string
            com = k.get_explanation(v)
            com = f" # {com}" if com else ""
            s = k.get_value_string(v)
            if "check" not in s:
                s, v = s.split("=")
                color = self.get_verdict_color(v)
                text = f"{s}{com}"
                writer.write(f"{color}{'['+v+']':<20}{RESET}├──{color}{text}{RESET}\n")
            else:
                writer.write(f"{'':<20}└──{s}{com}\n")

            self._print_source(writer, entity, 2, k)

    def print_report(self, writer: TextIO):
        """Print textual report"""
        cache: Dict[Entity, Verdict] = {}
        system_verdict = Verdict.PASS

        hosts = self.system.get_hosts()
        for h in hosts:
            if h.get_verdict(cache) == Verdict.FAIL:
                system_verdict = Verdict.FAIL

        self.print_title(self.get_title_text(system_verdict), "=", writer)
        self.print_title(f"{BOLD}{'Verdict:':<17}Hosts and Services:{RESET}", "-", writer, skip_first=True)

        rev_map: Dict[str, List[Host]] = {}
        for h in hosts:
            if not h.is_relevant():
                continue

            h_name = f"{h.name}"
            aggregate_verdict = f"{h.status.value}/{h.get_verdict(cache).value}"
            color = self.get_verdict_color(aggregate_verdict)
            writer.write(f"{color}{'['+aggregate_verdict+']':<17}{BOLD}{h_name}{RESET}\n")

            self._print_source(writer, h, 1)
            ads = [f"{a}" for a in sorted(h.addresses)]
            for a in ads:
                rev_map.setdefault(a, []).append(h)
            ads = [a for a in ads if a != h_name]
            if ads:
                writer.write(f"{'':<17}|  Addresses: {', '.join(ads)}\n")

            self.print_properties(h, writer)
            for i, s in enumerate(h.children):
                v = s.status_string()
                color = self.get_verdict_color(v)
                if i == len(h.children)-1 and len(h.components) == 0:
                    writer.write(f"{color}{'['+v+']':<17}{RESET}└──{color}{s.name}{RESET}\n")
                else:
                    writer.write(f"{color}{'['+v+']':<17}{RESET}├──{color}{s.name}{RESET}\n")
                self._print_source(writer, s, 2)
                self.print_properties(s, writer)

            for comp in h.components:
                writer.write(f"{'':<17}└──{comp.name} [Component]\n")
                sw_info = comp.info_string()
                if sw_info:
                    writer.write(SUB_INDENT + sw_info.replace("\n", "\n    ") + "\n")
                self._print_source(writer, comp, 2)
                self.print_properties(comp, writer)

        for ad, hs in sorted(rev_map.items()):
            if len(hs) > 1:
                self.logger.warning("DOUBLE mapped %s: %s", ad, ", ".join([f"{h}" for h in hs]))

        self.print_title(f"{BOLD}Connections\n{'Verdict:':<17}{'Source:':<33}Target:{RESET}", "-", writer)
        for conn in self.system.get_connections(relevant_only=False):
            stat = conn.con_type.value if conn.con_type == ConnectionType.LOGICAL else conn.status_string()
            color = self.get_verdict_color(stat)
            writer.write(f"{color}{'['+stat+']':<17}{conn.source.long_name():<32} {conn.target.long_name()}{RESET}\n")
            self._print_source(writer, conn, 2)
            self.print_properties(conn, writer)

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
