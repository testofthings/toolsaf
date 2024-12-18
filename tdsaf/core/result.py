"""Simple text report on the system status"""
#pylint: disable=too-many-boolean-expressions

import sys
import shutil
import logging
from functools import cached_property
from typing import TextIO, List, Dict, Tuple, Union
from colored import Fore, Style

from tdsaf.common.basics import ConnectionType
from tdsaf.common.entity import Entity
from tdsaf.common.verdict import Verdict
from tdsaf.core.model import Host, NetworkNode, Connection, Addressable, NodeComponent
from tdsaf.core.components import SoftwareComponent
from tdsaf.common.property import Properties, PropertyKey, PropertyVerdictValue
from tdsaf.core.registry import Registry


class Report:
    """Report of the system status"""
    def __init__(self, registry: Registry):
        self.registry = registry
        self.system = registry.system
        self.source_count = 3
        self.show = []
        self.no_truncate = False
        self.c = False
        self.logger = logging.getLogger("reporter")
        self.width = self.get_terminal_width()

    @cached_property
    def use_color(self) -> bool:
        """Determines if color text should be colored"""
        return self.c or sys.stdout.isatty()

    @cached_property
    def green(self) -> str:
        """Green color"""
        return Fore.green if self.use_color else ""

    @cached_property
    def yellow(self) -> str:
        """Yellow color"""
        return Fore.rgb(255,220,101) if self.use_color else ""

    @cached_property
    def red(self) -> str:
        """Red color"""
        return Fore.red if self.use_color else ""

    @cached_property
    def bold(self) -> str:
        """Bold text"""
        return Style.bold if self.use_color else ""

    @cached_property
    def reset(self) -> str:
        """Reset colors/styles"""
        return Style.reset if self.use_color else ""

    @cached_property
    def show_all(self) -> bool:
        """Should all info be printed without text truncation"""
        return "all" in self.show

    def get_system_verdict(self, cache: Dict) -> Verdict:
        """Get verdict for the entire system based on cached verdicts."""
        verdicts = cache.values()
        if Verdict.FAIL in verdicts:
            return Verdict.FAIL
        if Verdict.PASS in verdicts:
            return Verdict.PASS
        return Verdict.INCON

    def get_verdict_color(self, verdict: any) -> str:
        """Returns color value for Verdict or string"""
        if isinstance(verdict, Verdict):
            if verdict == Verdict.INCON:
                return ""
            return [self.red, self.green, self.yellow][[Verdict.FAIL, Verdict.PASS, Verdict.IGNORE].index(verdict)]
        if isinstance(verdict, str):
            verdict = verdict.lower()
            if "/" in verdict:
                v = verdict.split("/")[1]
                return [self.red, self.green, ""][["fail", "pass", "incon"].index(v)]
            if "pass" in verdict:
                return self.green
            if "fail" in verdict:
                return self.red
            if "ignore" in verdict:
                return self.yellow
        return ""

    def get_terminal_width(self) -> int:
        """Returns terminal width or fallback value"""
        w, _ = shutil.get_terminal_size(fallback=(90, 30))
        return w

    def crop_text(self, text: str) -> str:
        """Crop text to fit on one line. Cropping can be disabled with cmd argument"""
        if self.show_all or self.no_truncate:
            return text
        if len(text) > self.width:
            new_end = "\n" if "\n" in text else ""
            if self.reset != "" and self.reset in text:
                new_end = self.reset + new_end
            return text[:self.width - 3] + "..." + new_end
        return text

    def print_title(self, text: str, writer: TextIO,
                    top_symbol: str="", bottom_symbol: str="") -> None:
        """Writes title sections to the output"""
        if top_symbol:
            writer.write(top_symbol * self.width + "\n")
        writer.write(text + "\n")
        if bottom_symbol:
            writer.write(bottom_symbol * self.width + "\n")

    def get_properties_to_print(self, e: NetworkNode) -> Tuple[List[Tuple], int]:
        """Retuns properties that should be printed and the number of properties"""
        prop_items = [(k,v) for k,v in e.properties.items() if k!=Properties.EXPECTED]
        if self.show_all:
            return prop_items, len(prop_items)

        result = []
        for k, v in prop_items:
            if (is_inst:=isinstance(v, PropertyVerdictValue)) and (
                v.verdict == Verdict.FAIL or
                v.verdict == Verdict.IGNORE and "ignored" in self.show or
                v.verdict != Verdict.IGNORE and "properties" in self.show
            ) or not is_inst and "properties" in self.show:
                result += [(k, v)]
        return result, len(result)

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
        if (self.show_all or self.show and 'properties' in self.show) and len(c.properties) > 0:
            return "├──"
        if idx + 1 != len(h.components):
            return "│  "
        return "└──"

    def get_text(self, k: PropertyKey, v: any) -> str:
        """Get text to print"""
        value_string = k.get_value_string(v)
        comment = k.get_explanation(v)
        comment = f" # {comment}" if comment else ""
        if isinstance(v, PropertyVerdictValue) or "=verdict" in value_string.lower():
            value_string = value_string.split("=")[0]
        return f"{value_string}{comment}"

    def print_properties(self, entity: NetworkNode, writer: TextIO, leading: str="",
                         indent: int=0, is_last: bool=False):
        """Print properties from entity"""
        prop_items, num = self.get_properties_to_print(entity)

        set_indent = indent == 0
        if not set_indent and leading:
            indent -= 3

        k: PropertyKey
        for i, (k, v) in enumerate(prop_items):
            text = self.get_text(k, v)

            symbol = self.get_symbol_for_property(i, num)
            if set_indent:
                indent = 17 if isinstance(entity, Connection) else 20

            if leading:
                symbol = leading + "  " + symbol
                if set_indent:
                    indent -= 3

            if (v:=k.get_verdict(entity.properties)) is not None:
                color = self.get_verdict_color(v)
                writer.write(self.crop_text(
                    f"{color}{'['+v.value+']':<{indent}}{self.reset}{symbol}{color}{text}{self.reset}\n"
                ))
            else:
                writer.write(self.crop_text(f"{'':<{indent}}{symbol}{text}\n"))

            srcs = self._get_sources(entity, k)
            src_indent = 14 if isinstance(entity, Connection) else 17
            for src in srcs:
                if is_last:
                    if i == len(prop_items)-1:
                        writer.write(f"{'':<{src_indent}}         @{src}\n")
                    else:
                        writer.write(f"{'':<{src_indent}}   │     @{src}\n")
                else:
                    if i == len(prop_items)-1:
                        writer.write(f"{'':<{src_indent}}│        @{src}\n")
                    else:
                        writer.write(f"{'':<{src_indent}}│  │     @{src}\n")

    def get_connection_status(self, connection: Connection, cache: Dict) -> str:
        """Returns status string for a connection"""
        if connection.con_type == ConnectionType.LOGICAL:
            return connection.con_type.value
        v = connection.get_verdict(cache)
        if v not in [Verdict.PASS, Verdict.FAIL]:
            return connection.status.value
        return f"{connection.status.value}/{v.value}"

    def _get_addresses(self, e: Host) -> str:
        """FIXME"""
        ads = [f"{a}" for a in sorted(e.addresses)]
        ads = [a for a in ads if a != e.name]
        return ", ".join(ads)

    def _get_properties(self, entity: Host) -> Dict:
        """FIXME"""
        props = {}
        prop_items, _ = self.get_properties_to_print(entity)

        k: PropertyKey
        for _, (k, v) in enumerate(prop_items):
            text = self.get_text(k, v)
            v = k.get_verdict(entity.properties)

            props[k.get_name()] = {
                "srcs": self._get_sources(entity, k),
                "verdict": v.value if v is not None else None,
                "text": text
            }
        return props

    def _get_sub_structure(self, entity: Union[Host, Addressable, NodeComponent]) -> Dict:
        """FIXME"""
        return {
            "srcs": self._get_sources(entity),
            "verdict": entity.status_string(),
            "address": self._get_addresses(entity) if isinstance(entity, Host) else None,
            **self._get_properties(entity)
        }

    def build_structure(self, entities: List[Host]) -> Dict: # Or Connection
        """FIXME"""
        structure = {"hosts": {}}

        for e in entities:
            if not e.is_relevant():
                continue

            # Host
            structure["hosts"][e.name] = self._get_sub_structure(e)

            # Protocols
            for c in e.children:
                structure["hosts"][e.name][c.name] = self._get_sub_structure(c)

            # Components
            for c in e.components:
                structure["hosts"][e.name][c.name + " [Component]"] = self._get_sub_structure(c)

        return structure

    def build_connecion_structure(self, connections: List[Connection], cache: Dict) -> Dict:
        """FIXME"""
        structure = {"connections": []}
        for c in connections:
            structure["connections"].append({
                "verdict":self.get_connection_status(c, cache),
                "source": c.source.long_name(),
                "target": c.target.long_name(),
                "srcs": self._get_sources(c),
                **self._get_properties(c)
            })
        return structure

    def _print_text(self, text: str, verdict: str, lead: str, writer: TextIO,
                    indent: int=17, use_bold: bool=False) -> None:
        """FIXME"""
        text = self._crop_text(text, lead, indent)
        if verdict is not None:
            color = self.get_verdict_color(verdict)
            if use_bold:
                text = self.bold + text
            writer.write(
                f"{color}{'[' + verdict + ']':<{indent}}{self.reset}{lead}{color}{text}{self.reset}\n"
            )
        else:
            writer.write(f"{'':<{indent}}{lead}{text}\n")

    def print_connection_structure(self, c: Dict, writer: TextIO, lead: str="", symbol: str="") -> None:
        """FIXME"""
        v = c['verdict']
        children = [k for k in c if isinstance(c[k], dict)]
        c_lead = lead[:-3] + symbol
        if "source" in c:
            self._print_text(f"{c['source']:<33}{c['target']}", v, c_lead, writer)
        else:
            self._print_text(c["text"], v, c_lead, writer)

        c_lead = lead + "│  " if children else lead + "   "
        for src in c["srcs"]:
            self._print_text(f"@{src}", None, c_lead, writer)


        for child in children:
            symbol = "├──" if child != children[-1] else "└──"
            self.print_connection_structure(c[child], writer, lead=lead + "   ", symbol=symbol)


    def print_report(self, writer: TextIO):
        """Print textual report"""
        cache: Dict[Entity, Verdict] = {}

        hosts = self.system.get_hosts()
        for h in hosts:
            h.get_verdict(cache)

        rev_map: Dict[str, List[Host]] = {}

        system_verdict = self.get_system_verdict(cache)
        color = self.get_verdict_color(system_verdict)

        self.print_title(f"{self.bold}{'Verdict:':<17}System:{self.reset}", writer, "=", "-")
        writer.write(f"{color}{'['+system_verdict.value+']':<17}{self.bold}{self.system.long_name()}{self.reset}\n")
        self.print_properties(self.system, writer, indent=17)


        a="""
        self.print_title(f"{self.bold}{'Verdict:':<17}Hosts and Services:{self.reset}", writer, "=", "-")

        host_structure = self.build_structure(hosts)
        self.print_structure(-1, host_structure["hosts"], writer, "", False)


        self.print_title(
            f"{self.bold}Connections\n{'Verdict:':<17}{'Source:':<33}Target:{self.reset}", writer, "=", "-"
        )
        relevant_only = not (self.show_all or (self.show and "irrelevant" in self.show))
        connections = self.system.get_connections(relevant_only=relevant_only)
        connection_structure = self.build_connecion_structure(connections, cache)
        for connection in connection_structure["connections"]:
            self.print_connection_structure(connection, writer)

        return
        """

        for h in hosts:
            if not h.is_relevant():
                continue

            h_name = h.name
            aggregate_verdict = f"{h.status.value}/{h.get_verdict(cache).value}"
            color = self.get_verdict_color(aggregate_verdict)
            if "/Incon" in aggregate_verdict:
                aggregate_verdict = aggregate_verdict.split("/", maxsplit=1)[0]
            writer.write(self.crop_text(f"{color}{'['+aggregate_verdict+']':<17}{self.bold}{h_name}{self.reset}\n"))


            srcs = self._get_sources(h)
            if self.get_properties_to_print(h)[1] > 0:
                for src in srcs:
                    writer.write(f"{'':<17}│  │  @{src}\n")
            else:
                for src in srcs:
                    writer.write(f"{'':<17}│  @{src}\n")

            self.print_properties(h, writer, leading="│")

            ads = [f"{a}" for a in sorted(h.addresses)]
            for a in ads:
                rev_map.setdefault(a, []).append(h)
            ads = [a for a in ads if a != h_name]
            if ads:
                symbol = self.get_symbol_for_addresses(h)
                writer.write(self.crop_text(f"{'':<17}{symbol}Addresses: {', '.join(ads)}\n"))

            for i, s in enumerate(h.children):
                v = s.status_string()
                color = self.get_verdict_color(v)

                symbol = self.get_symbol_for_service(i, h)
                writer.write(self.crop_text(f"{color}{'['+v+']':<17}{self.reset}{symbol}{color}{s.name}{self.reset}\n"))

                srcs = self._get_sources(h)
                if self.get_properties_to_print(s)[1] >= 1:
                    for src in srcs:
                        writer.write(f"{'':<17}│  │  @{src}\n")
                elif i < len(h.children) - 1 or len(h.components) > 0:
                    for src in srcs:
                        writer.write(f"{'':<17}│     @{src}\n")
                else:
                    for src in srcs:
                        writer.write(f"{'':<17}      @{src}\n")

                self.print_properties(s, writer, leading="│", is_last=len(h.components)==0)

            for i, comp in enumerate(h.components):
                symbol = self.get_symbol_for_component(i, h)
                writer.write(self.crop_text(f"{'':<17}{symbol}{comp.name} [Component]\n"))
                sw_info = comp.info_string()
                if sw_info:
                    symbol = self.get_symbol_for_info(i, h, comp)
                    writer.write(self.crop_text(f"{'':<20}{symbol}Info: {sw_info}\n"))

                srcs = self._get_sources(comp)
                for src in srcs:
                    if self.get_properties_to_print(comp)[1] == 0:
                        if i != len(h.components)-1:
                            writer.write(f"{'':<17}│     @{src}\n")
                        else:
                            writer.write(f"{'':<17}      @{src}\n")
                    else:
                        if i != len(h.components)-1:
                            writer.write(f"{'':<17}│  │  @{src}\n")
                        else:
                            writer.write(f"{'':<17}   │  @{src}\n")

                leading = "│" if i != len(h.components)-1 else ""
                self.print_properties(comp, writer, leading=leading, is_last=i==len(h.components)-1)

        for ad, hs in sorted(rev_map.items()):
            if len(hs) > 1:
                self.logger.warning("DOUBLE mapped %s: %s", ad, ", ".join([f"{h}" for h in hs]))

        self.print_title(
            f"{self.bold}Connections\n{'Verdict:':<17}{'Source:':<33}Target:{self.reset}", writer, "=", "-"
        )

        relevant_only = not (self.show_all or (self.show and "irrelevant" in self.show))
        connections = self.system.get_connections(relevant_only=relevant_only)

        for conn in connections:
            stat = self.get_connection_status(conn, cache)
            color = self.get_verdict_color(stat)
            writer.write(self.crop_text(
                f"{color}{'['+stat+']':<17}{conn.source.long_name():<32} {conn.target.long_name()}{self.reset}\n"
            ))

            srcs = self._get_sources(conn)
            if self.get_properties_to_print(conn)[1] >= 1:
                for src in srcs:
                    writer.write(f"{'':<17}│  @{src}\n")
            else:
                for src in srcs:
                    writer.write(f"{'':<20}@{src}\n")

            self.print_properties(conn, writer, is_last=True)

    def _get_sources(self, entity: Entity, key: PropertyKey=Properties.EXPECTED) -> List[str]:
        """Returns max self.source_count source strs for entity; if any"""
        if not self.source_count:
            return []
        sources = set(filter(None, [
            e.event.evidence.get_reference()
            for e in self.registry.logging.get_log(entity, {key})
        ]))

        return list(sources)[:self.source_count]

    def _crop_text(self, text: str, lead: str, indent: int) -> str:
        total_len = len(text) + len(lead) + indent
        if total_len > self.width:
            return text[:(self.width - len(lead) - indent - 3)] + "..."
        return text

    def print_structure(self, lvl: int, j: Dict, writer: TextIO, lead: str="", parent_has_next: bool=False) -> None:
        """FIXME"""
        for i, entry in enumerate(j):
            if entry == "verdict":
                continue

            # Hosts are at lvl -1
            if lvl < 0:
                v = j[entry]["verdict"]
                self._print_text(entry, v, "", writer, use_bold=True)
                self.print_structure(lvl+1, j[entry], writer, "│  ", False)


            elif isinstance(j[entry], dict):
                v = j[entry]['verdict']
                symbol = "└──" if i == len(j)-1 else "├──"
                # Strip end from lead, it will be replace by symbol
                c_lead = lead[:-3] + symbol
                text = j[entry]["text"] if "text" in j[entry] else entry

                if v is not None:
                    self._print_text(text, v, c_lead, writer)
                else:
                    self._print_text(text, None, c_lead, writer)

                # Check entity relations
                parent_has_next = any(
                    (isinstance(j[k], dict) for k in list(j.keys())[i:] if k != entry)
                ) if lvl>=1 else False
                entity_has_children = any(isinstance(j[entry][k], dict) for k in j[entry] if k != entry)
                is_last_entity = i == len(j)-1

                if not is_last_entity:
                    c_lead = lead + "│  " if entity_has_children else lead + "   "
                    self.print_structure(lvl+1, j[entry], writer, lead=c_lead, parent_has_next=parent_has_next)
                else:
                    # Special handling for symbols of last entities
                    if lvl == 0:
                        lead = "   "
                    if entity_has_children:
                        # Remove 2nd to last "|" from lead, so symbols allign properly
                        c_lead = lead[:-3] + "   " + "│  "
                    else:
                        c_lead = lead + "   "
                    self.print_structure(lvl+1, j[entry], writer, lead=c_lead, parent_has_next=parent_has_next)

            else:
                has_next_entity = any(isinstance(j[k], dict) for k in j)
                c_lead = lead
                if not has_next_entity:
                    if lvl > 1 and not parent_has_next:
                        c_lead = lead[::-1].replace('│', ' ', 1)[::-1]

                if entry == "srcs":
                    for src in j[entry]:
                        self._print_text(f"@{src}", None, c_lead, writer)

                if entry == "address" and j[entry] is not None:
                    self._print_text(f"Addresses: {j[entry]}", None, c_lead, writer)
