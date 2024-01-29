import logging
from typing import TextIO, List, Dict, Optional, Self, Set

from tcsfw.address import Protocol
from tcsfw.entity import Entity
from tcsfw.model import IoTSystem, Host, HostType, ConnectionType, Service, NetworkNode
from tcsfw.property import Properties
from tcsfw.registry import Registry
from tcsfw.verdict import Status, Verdict

# Keywords for verdicts
FAIL = "fail"
PASS = "pass"
INCONCLUSIVE = "-"


class Report:
    """Report of the system status"""
    def __init__(self, registry: Registry):
        self.registry = registry
        self.system = registry.system
        self.logger = logging.getLogger("reporter")

    def print_properties(self, entity: NetworkNode, indent: str, writer: TextIO):
        """Print properties from entity"""
        for k, v in entity.properties.items():
            if k == Properties.EXPECTED:
                continue  # encoded into status string
            com = k.get_explanation(v)
            com = f" # {com}" if com else ""
            writer.write(f"{indent}{k.get_value_string(v)}{com}\n")

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
            ads = [f"{a}" for a in sorted(h.addresses)]
            for a in ads:
                rev_map.setdefault(a, []).append(h)
            ads = [a for a in ads if a != h_name]
            if ads:
                writer.write(f"  Addresses: " + " ".join(ads) + "\n")

            for comp in h.components:
                writer.write(f"  {comp.name} [Component]\n")
                sw_info = comp.info_string()
                if sw_info:
                    writer.write("    " + sw_info.replace("\n", "\n    ") + "\n")
                self.print_properties(comp, "    ", writer)

            self.print_properties(h, "  ", writer)
            for s in h.children:
                auth = f" auth={s.authentication}" if isinstance(s, Service) else ""
                writer.write(f"  {s.name} [{s.status_string()}]{auth}\n")
                self.print_properties(s, "    ", writer)
        for ad, hs in sorted(rev_map.items()):
            if len(hs) > 1:
                self.logger.warning(f"DOUBLE mapped {ad}: " + ", ".join([f"{h}" for h in hs]))

        writer.write("== Connections ==\n")
        for conn in self.system.get_connections(relevant_only=False):
            stat = conn.con_type.value if conn.con_type == ConnectionType.LOGICAL else conn.status_string()
            writer.write(f"{conn.source.long_name():>30} ==> {conn.target.long_name()} [{stat}]\n")

    def _create_report(self) -> 'TabularReport':
        """Create report objects"""
        report = TabularReport()
        report.sections.append(self._list_nodes())
        report.sections.append(self._list_services())
        report.sections.append(self._list_connections())
        report.sections.append(self._list_protocols())
        report.sections.append(self._list_check_coverage())
        report.finish()
        return report

    def tabular(self, writer: TextIO, latex=False):
        """Give tabular CSV or LaTeX output"""
        report = self._create_report()
        if latex:
            for s in report.to_latex():
                writer.write(f"{s}\n")
        else:
            writer.write(f"{report}")

    def json(self) -> Dict:
        """Give JSON tabular output"""
        report = self._create_report()
        return report.to_json()

    def _list_nodes(self) -> 'ReportSection':
        local_n = ReportRow("Local nodes", verified=0)
        remote_n = ReportRow("Remote nodes", verified=0)
        admin_n = ReportRow("Administrative nodes", verified=0)
        un_n = ReportRow("Unexpected nodes", claimed=None, verified=0)
        hosts = self.system.get_hosts()
        for h in hosts:
            if not h.is_relevant():
                continue
            claimed = 1 if h.status == Status.EXPECTED else 0
            verified = 1 if Properties.EXPECTED.get_verdict(h.properties) == Verdict.PASS else 0
            if claimed == verified == 0:
                continue
            admin = h.host_type == HostType.ADMINISTRATIVE
            is_local = not h.is_global()
            self.logger.info("Host %s claim=%s verify=%s local=%s admin=%s ver=%s", h.name, claimed, verified,
                             is_local, admin, h.status_string())
            if not claimed:
                un_n.verified += verified
                un_n.entities.add(h)
            elif admin:
                admin_n.claimed += claimed
                admin_n.verified += verified
                admin_n.entities.add(h)
            elif is_local:
                local_n.claimed += claimed
                local_n.verified += verified
                local_n.entities.add(h)
            else:
                remote_n.claimed += claimed
                remote_n.verified += verified
                remote_n.entities.add(h)
        return ReportSection("List / network nodes", [local_n, remote_n, admin_n, un_n])

    def _list_services(self) -> 'ReportSection':
        local_n = ReportRow("Local services", verified=0)
        remote_n = ReportRow("Remote services", verified=0)
        admin_n = ReportRow("Administrative services", verified=0)
        un_n = ReportRow("Unexpected services", claimed=None, verified=0)
        hosts = self.system.get_hosts()
        for h in hosts:
            if not h.is_relevant():
                continue
            for s in h.children:
                if not s.is_relevant():
                    continue
                claimed = 1 if h.status == Status.EXPECTED else 0
                verified = 1 if Properties.EXPECTED.get_verdict(h.properties) == Verdict.PASS else 0
                if claimed == verified == 0:
                    continue
                admin = s.host_type == HostType.ADMINISTRATIVE
                is_local = not s.is_global()
                self.logger.info("Service %s %s claim=%s verify=%s local=%s admin=%s ver=%s", h.name, s.name,
                                 claimed, verified, is_local, admin, s.status_string())
                if not claimed:
                    un_n.verified += verified
                    un_n.entities.add(s)
                elif admin:
                    admin_n.claimed += claimed
                    admin_n.verified += verified
                    admin_n.entities.add(s)
                elif is_local:
                    local_n.claimed += claimed
                    local_n.verified += verified
                    local_n.entities.add(s)
                else:
                    remote_n.claimed += claimed
                    remote_n.verified += verified
                    remote_n.entities.add(s)
        return ReportSection("List / services", [local_n, remote_n, admin_n, un_n])

    def _list_connections(self) -> 'ReportSection':
        encrypt_n = ReportRow("Encrypted connections", verified=0)
        plain_n = ReportRow("Plaintext connections", verified=0)
        admin_n = ReportRow("Administrative connections", verified=0)
        un_n = ReportRow("Unexpected connections", claimed=None, verified=0)
        hosts = self.system.get_hosts()
        conns = set()
        for h in hosts:
            if not h.is_relevant():
                continue
            for c in h.connections:
                if c in conns or not c.is_relevant() or c.con_type == ConnectionType.LOGICAL:
                    continue
                conns.add(c)
                claimed = 1 if h.status == Status.EXPECTED else 0
                verified = 1 if Properties.EXPECTED.get_verdict(h.properties) == Verdict.PASS else 0
                if claimed == verified == 0:
                    continue
                encrypt = c.con_type == ConnectionType.ENCRYPTED
                admin = c.con_type == ConnectionType.ADMINISTRATIVE
                self.logger.info("Conn %s => %s claim=%s verify=%s local=%s admin=%s ver=%s",
                                 c.source.long_name(), c.target.long_name(),
                                 claimed, verified, encrypt, admin, c.status_string())
                if not claimed:
                    un_n.verified += verified
                    un_n.entities.add(c)
                elif admin:
                    admin_n.claimed += claimed
                    admin_n.verified += verified
                    admin_n.entities.add(c)
                elif encrypt:
                    encrypt_n.claimed += claimed
                    encrypt_n.verified += verified
                    encrypt_n.entities.add(c)
                else:
                    plain_n.claimed += claimed
                    plain_n.verified += verified
                    plain_n.entities.add(c)
        return ReportSection("List / connections", [encrypt_n, plain_n, admin_n, un_n])

    def _list_protocols(self) -> 'ReportSection':
        by_protocol: Dict[Protocol, ReportRow] = {}
        admin_n = ReportRow("Administrative", verified=0)
        un_n = ReportRow("Undefined", verified=0, is_coverage=False)
        hosts = self.system.get_hosts()
        for h in hosts:
            if not h.is_relevant():
                continue
            for s in h.children:
                if not s.is_relevant() or not isinstance(s, Service):
                    continue
                pro = s.protocol
                claimed = 1 if h.status == Status.EXPECTED else 0
                verified = 1 if Properties.EXPECTED.get_verdict(h.properties) == Verdict.PASS else 0
                if claimed == verified == 0:
                    continue
                admin = s.host_type == HostType.ADMINISTRATIVE
                self.logger.info("Protocol %s %s %s claim=%s verify=%s admin=%s ver=%s",
                                 h.name, s.name, pro.value if pro else "???",
                                 claimed, verified, admin, s.status_string())
                if not claimed:
                    un_n.verified += verified
                    un_n.entities.add(s)
                elif admin:
                    admin_n.claimed += claimed
                    admin_n.verified += verified
                    admin_n.entities.add(s)
                elif pro is Protocol.ANY:
                    un_n.claimed += claimed
                    un_n.verified += verified
                    un_n.entities.add(s)
                else:
                    rn = by_protocol.get(pro)
                    if rn is None:
                        rn = by_protocol.setdefault(pro, ReportRow(pro.value.upper(), verified=0))
                    rn.claimed += claimed
                    rn.verified += verified
                    rn.entities.add(s)
        rows = [admin_n]
        rows.extend([p for _, p in sorted(by_protocol.items(), key=lambda p: p[0].value)])
        rows.append(un_n)
        return ReportSection("List / protocols", rows)

    def _list_check_coverage(self) -> 'ReportSection':
        check_n = ReportRow("Checked services", verified=0)
        fail_n = ReportRow("Failed service checks", verified=0)
        admin_n = ReportRow("Administrative services", verified=0)
        un_n = ReportRow("Other unchecked services", verified=0, is_coverage=False)
        hosts = self.system.get_hosts()
        for h in hosts:
            if not h.is_relevant():
                continue
            for s in h.children:
                if not s.is_relevant() or not isinstance(s, Service):
                    continue
                claimed = 0
                checked = 0
                failed = 0
                if s.claims:
                    claimed = 1
                    checked = 0
                    # service-specific claims made
                    for c, v in s.claims.items():
                        if v.verdict == Verdict.PASS:
                            checked = 1  # checked ok
                        elif v.verdict not in {Verdict.INCON, Verdict.IGNORE}:
                            failed = 1  # at least one claim failed
                else:
                    # no special claims
                    if Properties.EXPECTED.get_verdict(s.properties) == Verdict.PASS:
                        checked = 1
                admin = s.host_type == HostType.ADMINISTRATIVE
                self.logger.info("Checked %s %s claim=%s fail=%s check=%s admin=%s ver=%s", h.name, s.name,
                                 claimed, failed, checked, admin, s.status_string())
                if failed:
                    fail_n.verified += checked
                    fail_n.entities.add(s)
                if claimed:
                    check_n.claimed += claimed
                    check_n.verified += checked
                    check_n.entities.add(s)
                elif admin:
                    admin_n.claimed += 1
                    admin_n.verified += checked
                    admin_n.entities.add(s)
                else:
                    un_n.claimed += 1
                    un_n.verified += checked
                    un_n.entities.add(s)
        return ReportSection("Check / services", [check_n, fail_n, admin_n, un_n])


class ReportRow:
    """Tabular report row"""
    def __init__(self, name: str, claimed: Optional[float] = 0, verified: Optional[float] = None, is_coverage=True):
        self.name = name
        self.claimed = 0 if claimed is None else claimed
        self.is_claimed = claimed is not None
        self.verified = verified
        self.verdict = ""
        self.is_coverage = is_coverage
        self.description = ""
        self.entities: Set[Entity] = set()

    @classmethod
    def color_for_verdict(cls, verdict: str, title=False, row_color=False):
        color = r"Inco"
        if verdict == 'pass':
            color = r"Pass"
        elif verdict == FAIL:
            color = r"Fail"
        if title:
            color = f"Title{color}"
        if row_color:
            return r"\rowcolor{" + color + "}"
        return r"\cellcolor{" + color + "}"

    def to_latex(self, title=False, name=True, compare_to: List['ReportRow'] = None) -> str:
        compare_to = compare_to or []

        # NOTE: As comparison for limited purpose, it simply assumes reports have the same lines
        if compare_to:
            assert all(r.name == self.name for r in compare_to)

        verdict = self.verdict
        for co in compare_to:
            if co.verdict == FAIL or (verdict == PASS and co.verdict == INCONCLUSIVE):
                verdict = co.verdict

        c = f"{self.claimed:1.0f}" if self.is_claimed else ""
        if title:
            v = f"{(self.verified or 0) * 100:1.0f}\\%"
        else:
            v = "" if self.verified is None else f"{self.verified:1.0f}"
        s = []
        if name:
            color = self.color_for_verdict(verdict, title=title)
            s = [f"{color}{self.name}"]
        color = self.color_for_verdict(self.verdict, title=title)
        s.extend([f"{color}{c}", f"{color} {v}", f"{color} {self.verdict}"])
        if title:
            s = [f"{{\\bf {c}}}" for c in s]
        if compare_to:
            other = ""
            for o_row in compare_to:
                other += f" {o_row.to_latex(title=title, name=False)}"
            s.append(other)
        return f" & ".join(s) + (r" \\" if name else "")

    def to_cvs(self, title=False) -> str:
        n = f"{self.name},"
        c = f"{self.claimed:1.0f}"
        if title:
            v = f"{(self.verified or 0) * 100:1.0f}%"
        else:
            v = "" if self.verified is None else f"{self.verified:1.0f}"
        return f"{n:<30}{c:>5},{v:>5},{self.verdict:<5}"

    def to_json(self, title=False) -> Dict:
        js = {
            "title": self.name,
            "claimed": f"{self.claimed:1.0f}",
        }
        if title:
            js["verified"] = f"{(self.verified or 0) * 100:1.0f}%"
        else:
            js["verified"] = None if self.verified is None else f"{self.verified:1.0f}"
        js["verdict"] = self.verdict
        js["entities"] = sorted([e.long_name() for e in self.entities])
        js["info"] = self.description
        return js

    def __repr__(self):
        return self.to_cvs()


class ReportSection:
    """Tabular report section"""
    def __init__(self, title: str, rows: List[ReportRow] = None):
        self.rows: List[ReportRow] = [ReportRow(title)]
        if rows:
            self.rows.extend(rows)

    def title_row(self) -> ReportRow:
        """Access the title row"""
        return self.rows[0]

    def finish(self):
        """Finnish percentages and verdict"""
        claim = 0
        verify = 0
        failed = 0
        verified = any([r.verified > 0 for r in self.rows[1:]])
        for r in self.rows[1:]:
            claim += r.claimed
            if r.verified is None or not verified:
                r.verdict = INCONCLUSIVE
            elif r.verified <= r.claimed:
                # part or all verified
                if r.is_coverage:
                    verify += r.verified
                    r.verdict = PASS if r.verified == r.claimed else INCONCLUSIVE
                else:
                    # only zero is good
                    r.verdict = PASS if r.claimed == 0 else INCONCLUSIVE
            else:
                # more verified, must be unexpected stuff
                failed += r.verified
                r.verdict = FAIL
        title = self.rows[0]
        title.claimed = claim
        if claim > 0:
            title.verified = verify / claim
        if failed > 0:
            title.verdict = FAIL
        elif verify * 2 >= claim:
            title.verdict = PASS
        else:
            title.verdict = INCONCLUSIVE

    def to_latex(self, compare_to: List['ReportSection'] = None) -> List[str]:
        compare_to = compare_to or []

        # NOTE: As comparison for limited purpose, it simply assumes reports have the same lines
        if compare_to:
            assert all(s.rows[0].name == self.rows[0].name for s in compare_to)

        cot = [o_sec.rows[0] for o_sec in compare_to] if compare_to else []
        s = [self.rows[0].to_latex(title=True, compare_to=cot)]
        s.append(r"\hline")
        for i, r in enumerate(self.rows[1:]):
            cot = [o_sec.rows[i + 1] for o_sec in compare_to] if compare_to else []
            s.append(r.to_latex(compare_to=cot))
            s.append(r"\hline")
        return s

    def to_json(self) -> Dict:
        rs = [r.to_json(title=not i) for i, r in enumerate(self.rows)]
        return {"title": self.title_row().name, "rows": rs}

    def __repr__(self):
        rs = [self.rows[0].to_cvs(title=True)]
        rs.extend([f"{r}" for r in self.rows[1:]])
        return "\n".join(rs)


class TabularReport:
    """Tabular report"""
    def __init__(self, *section: ReportSection):
        self.product_name = ""
        self.sections: List[ReportSection] = section or []

    def finish(self) -> Self:
        """Finnish report data"""
        for s in self.sections:
            s.finish()
        return self

    def to_latex(self, compare_to: List['TabularReport'] = None, truncated=False) -> List[str]:
        compare_to = compare_to or []
        rc = 1 + len(compare_to)
        s = [r"\begin{tabular}{|l|" + "c|c|c|" * rc + "}"]
        s.append(r"\hline")
        if self.product_name:
            for n in [self.product_name] + [r.product_name for r in compare_to]:
                s.append(r"& \multicolumn{3}{|c|}{" + n + "}")
            s.append(r"\\ \hline")
        s.append(r"& {\bf Claimed} & {\bf Verified} & {\bf Verdict} " * rc)
        s.append(r"\\ \hline")
        for i, sec in enumerate(self.sections):
            cot = [o_rep.sections[i] for o_rep in compare_to] if compare_to else []
            s.extend(sec.to_latex(compare_to=cot))
        if truncated:
            s.append(f" ... " + "& ... " * rc * 3)
            s.append(r"\\ \hline")
        s.append(r"\end{tabular}")
        return s

    def to_json(self) -> Dict:
        s = [s.to_json() for s in self.sections]
        return {"sections": s}

    def __repr__(self):
        return "\n".join([f"{s}" for s in self.sections]) + "\n"


if __name__ == "__main__":
    # NOTE: Main generated a sample table used in article!
    product_a = TabularReport(
        ReportSection(
            "List / network nodes", rows=[
                ReportRow("Local nodes", 3, 3),
                ReportRow("Remote nodes", 5, 5),
                ReportRow("Administrative nodes", 2, 2),
                ReportRow("Unexpected nodes", None, 0),
            ]),
        ReportSection(
            "List / services", rows=[
                ReportRow("Local services", 3, 1),
                ReportRow("Remote services", 5, 5),
                ReportRow("Administrative services", 7, 7),
                ReportRow("Unexpected services", None, 0),
            ]),
        ReportSection(
            "List / connections", rows=[
                ReportRow("Encrypted connections", 7, 6),
                ReportRow("Plaintext connections", 1, 1),
                ReportRow("Administrative connections", 6, 6),
                ReportRow("Unexpected connections", None, 0),
            ]),
    ).finish()
    product_a.product_name = "Product A"
    product_b = TabularReport(
        ReportSection(
            "List / network nodes", rows=[
                ReportRow("Local nodes", 2, 2),
                ReportRow("Remote nodes", 2, 2),
                ReportRow("Administrative nodes", 3, 3),
                ReportRow("Unexpected nodes", None, 0),
            ]),
        ReportSection(
            "List / services", rows=[
                ReportRow("Local services", 2, 1),
                ReportRow("Remote services", 2, 2),
                ReportRow("Administrative services", 6, 6),
                ReportRow("Unexpected services", None, 1),
            ]),
        ReportSection(
            "List / connections", rows=[
                ReportRow("Encrypted connections", 2, 1),
                ReportRow("Plaintext connections", 5, 5),
                ReportRow("Administrative connections", 5, 5),
                ReportRow("Unexpected connections", None, 1),
            ]),
    ).finish()
    product_b.product_name = "Product B"
    print("\n".join(product_a.to_latex(compare_to=[product_b], truncated=True)) + "\n")
