"""Simple text report on the system status"""

import sys
import shutil
import logging
from typing import TextIO, List, Dict
from colored import Fore, Style

from tdsaf.common.basics import ConnectionType
from tdsaf.common.entity import Entity
from tdsaf.common.verdict import Verdict
from tdsaf.core.model import Host, NetworkNode, Connection
from tdsaf.core.components import SoftwareComponent
from tdsaf.common.property import Properties, PropertyKey, PropertyVerdictValue
from tdsaf.core.registry import Registry


OUTPUT_REDIRECTED = not sys.stdout.isatty()
GREEN = Fore.green if not OUTPUT_REDIRECTED else ""
YELLOW = Fore.rgb(255,220,101) if not OUTPUT_REDIRECTED else ""
RED = Fore.red if not OUTPUT_REDIRECTED else ""
BOLD = Style.bold if not OUTPUT_REDIRECTED else ""
RESET = Style.reset if not OUTPUT_REDIRECTED else ""


class Report:
    """Report of the system status"""
    def __init__(self, registry: Registry):
        self.registry = registry
        self.system = registry.system
        self.source_count = 3
        self.verbose = False
        self.show = []
        self.no_truncate = False
        self.logger = logging.getLogger("reporter")
        self.width = self.get_terminal_width()

    def get_verdict_color(self, verdict: any) -> str:
        """Returns color value for Verdict or string"""
        if isinstance(verdict, Verdict):
            if verdict == Verdict.INCON:
                return ""
            return [RED, GREEN, YELLOW][[Verdict.FAIL, Verdict.PASS, Verdict.IGNORE].index(verdict)]
        if isinstance(verdict, str):
            verdict = verdict.lower()
            if "/" in verdict:
                v = verdict.split("/")[1]
                return [RED, GREEN, ""][["fail", "pass", "incon"].index(v)]
            if "pass" in verdict:
                return GREEN
            if "fail" in verdict:
                return RED
            if "ignore" in verdict:
                return YELLOW
        return ""

    def get_terminal_width(self) -> int:
        """Returns terminal width or fallback value"""
        w, _ = shutil.get_terminal_size(fallback=(90, 30))
        return w

    def crop_text(self, text: str) -> str:
        """Crop text to fit on one line. Cropping can be disabled with cmd argument"""
        if self.verbose or self.no_truncate:
            return text
        if len(text) > self.width:
            new_end = "\n" if "\n" in text else ""
            if RESET != "" and RESET in text:
                new_end = RESET + new_end
            return text[:self.width - 3] + "..." + new_end
        return text

    def print_title(self, text: str, symbol: str, writer: TextIO, skip_first: bool=False) -> None:
        """Writes title sections to the output"""
        if not skip_first:
            writer.write(symbol * self.width + "\n")
        writer.write(text + "\n")
        writer.write(symbol * self.width + "\n")

    def get_title_text(self, verdict: any) -> str:
        """Returns the main title of the output"""
        color = self.get_verdict_color(verdict)
        if isinstance(verdict, Verdict):
            verdict = verdict.value
        return f"{'Report for:':<16} {BOLD}{self.system.long_name()}{RESET}\n" + \
                f"{color}{'Verdict:':<16} {BOLD}{verdict}{RESET}"

    def get_properties_to_print(self, e: NetworkNode) -> tuple[list[tuple], int]:
        """Retuns properties that should be printed and the number of properties"""
        prop_items = [(k,v) for k,v in e.properties.items() if k!=Properties.EXPECTED]
        if self.verbose:
            return prop_items, len(prop_items)
        if "ignored" in self.show and "properties" not in self.show:
            prop_items = [(k,v) for k,v in prop_items\
                          if isinstance(v, PropertyVerdictValue) and v.verdict==Verdict.IGNORE]
        elif "ignored" not in self.show:
            prop_items = [(k,v) for k,v in prop_items\
                          if not isinstance(v, PropertyVerdictValue) or v.verdict!=Verdict.IGNORE]
        return prop_items, len(prop_items)

    def get_symbol_for_addresses(self, h: Host) -> str:
        """Returns appropriate dir tree symbol for addresses"""
        if len(h.components) == 0 and len(h.children) == 0:
            return "└──"
        return "│  "

    def get_symbol_for_property(self, idx: int, total_num: int) -> str:
        """Returns appropriate dir tree symbol for property"""
        if idx + 1 < total_num:
            return "├──"
        return "└──"

    def get_symbol_for_service(self, idx: int, h: Host) -> str:
        """Returns appropriate dir tree symbol for service"""
        if idx + 1 == len(h.children) and len(h.components) == 0:
            return "└──"
        return "├──"

    def get_symbol_for_component(self, idx: int, h: Host) -> str:
        """Returns appropriate dir tree symbol for component"""
        if idx + 1 == len(h.components) or len(h.components) == 1:
            return "└──"
        return "├──"

    def get_symbol_for_info(self, idx: int, h: Host, c: SoftwareComponent) -> str:
        """Returns appropriate dir tree symbol for info"""
        if (self.verbose or self.show and 'properties' in self.show) and len(c.properties) > 0:
            return "├──"
        if idx + 1 != len(h.components):
            return "│  "
        return "└──"

    def print_properties(self, entity: NetworkNode, writer: TextIO, leading: str=""):
        """Print properties from entity"""
        if not self.show and not self.verbose:
            return

        prop_items, num = self.get_properties_to_print(entity)
        k: PropertyKey
        for i, (k, v) in enumerate(prop_items):
            com = k.get_explanation(v)
            com = f" # {com}" if com else ""
            s = k.get_value_string(v)

            symbol = self.get_symbol_for_property(i, num)
            indent = 17 if isinstance(entity, Connection) else 20

            if leading != "":
                symbol = leading + "  " + symbol
                indent -= 3

            if isinstance(v, PropertyVerdictValue):
                s = s.split("=")[0]
                color = self.get_verdict_color(v.verdict)
                text = f"{s}{com}"
                writer.write(self.crop_text(
                    f"{color}{'['+v.verdict.value+']':<{indent}}{RESET}{symbol}{color}{text}{RESET}\n"
                ))
            else:
                writer.write(self.crop_text(f"{'':<{indent}}{symbol}{s}{com}\n"))

            self._print_source(writer, entity, 2, k)

    def get_connection_status(self, connection: Connection, cache: dict) -> str:
        """Returns status string for a connection"""
        if connection.con_type == ConnectionType.LOGICAL:
            return connection.con_type.value
        v = connection.get_verdict(cache)
        if v not in [Verdict.PASS, Verdict.FAIL]:
            return connection.status.value
        return f"{connection.status.value}/{v.value}"

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

            h_name = h.name
            aggregate_verdict = f"{h.status.value}/{h.get_verdict(cache).value}"
            color = self.get_verdict_color(aggregate_verdict)
            if "/Incon" in aggregate_verdict:
                aggregate_verdict = aggregate_verdict.split("/", maxsplit=1)[0]
            writer.write(self.crop_text(f"{color}{'['+aggregate_verdict+']':<17}{BOLD}{h_name}{RESET}\n"))

            self._print_source(writer, h, 1)
            ads = [f"{a}" for a in sorted(h.addresses)]
            for a in ads:
                rev_map.setdefault(a, []).append(h)
            ads = [a for a in ads if a != h_name]
            if ads:
                symbol = self.get_symbol_for_addresses(h)
                writer.write(self.crop_text(f"{'':<17}{symbol}Addresses: {', '.join(ads)}\n"))

            self.print_properties(h, writer, leading="│")
            for i, s in enumerate(h.children):
                v = s.status_string()
                color = self.get_verdict_color(v)

                symbol = self.get_symbol_for_service(i, h)
                writer.write(self.crop_text(f"{color}{'['+v+']':<17}{RESET}{symbol}{color}{s.name}{RESET}\n"))
                self._print_source(writer, s, 2)

                if i < len(h.children)-1:
                    self.print_properties(s, writer, leading="│")

            for i, comp in enumerate(h.components):
                symbol = self.get_symbol_for_component(i, h)
                writer.write(self.crop_text(f"{'':<17}{symbol}{comp.name} [Component]\n"))
                sw_info = comp.info_string()
                if sw_info:
                    symbol = self.get_symbol_for_info(i, h, comp)
                    writer.write(self.crop_text(f"{'':<20}{symbol}Info: {sw_info}\n"))
                self._print_source(writer, comp, 2)
                leading = "│" if i != len(h.components)-1 else ""
                self.print_properties(comp, writer, leading=leading)

        for ad, hs in sorted(rev_map.items()):
            if len(hs) > 1:
                self.logger.warning("DOUBLE mapped %s: %s", ad, ", ".join([f"{h}" for h in hs]))

        self.print_title(f"{BOLD}Connections\n{'Verdict:':<17}{'Source:':<33}Target:{RESET}", "-", writer)
        relevant_only = not (self.verbose or (self.show and "irrelevant" in self.show))
        for conn in self.system.get_connections(relevant_only=relevant_only):
            stat = self.get_connection_status(conn, cache)
            color = self.get_verdict_color(stat)
            writer.write(self.crop_text(
                f"{color}{'['+stat+']':<17}{conn.source.long_name():<32} {conn.target.long_name()}{RESET}\n"
            ))
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
