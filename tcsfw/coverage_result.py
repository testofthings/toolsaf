import logging
import os
import textwrap
from typing import TextIO, Tuple, Dict, Optional, List, Set, Callable, Iterator

from tcsfw.claim_coverage import RequirementClaimMapper, ClaimMapping, RequirementStatus
from tcsfw.claim_set import ClaimContext
from tcsfw.default_requirements import DEFAULT
from tcsfw.entity import Entity, ClaimStatus, ClaimAuthority
from tcsfw.etsi_ts_103_701 import ETSI_TS_103_701, ETSI_TS_103_701_FIN
from tcsfw.event_logger import EventLogger
from tcsfw.model import IoTSystem
from tcsfw.property import PropertyKey, Properties
from tcsfw.requirement import Specification, Requirement
from tcsfw.verdict import Verdict


class CoverageReport:
    """Report of the system status"""
    def __init__(self, logger: EventLogger, coverage: RequirementClaimMapper, details=True):
        self.system = logger.get_system()
        self.logging = logger
        self.coverage = coverage
        self.details = details
        self.logger = logging.getLogger("report")

    @classmethod
    def load_specification(self, identifier: str) -> Specification:
        """Load specification by name"""
        if not identifier or identifier == DEFAULT.specification_id:
            return DEFAULT
        if identifier == ETSI_TS_103_701.specification_id:
            return ETSI_TS_103_701
        if identifier == ETSI_TS_103_701_FIN.specification_id:
            return ETSI_TS_103_701_FIN
        raise FileNotFoundError(f"Unknown specification '{identifier}'")

    @classmethod
    def _list_properties(cls, status: RequirementStatus) -> Dict[PropertyKey, bool]:
        """List properties resolved for a claim"""
        r = {}
        for ps in status.context.properties.values():
            for p, v in ps.items():
                r[p] = True if v else False  # boolean mapping
        return r

    def _get_mappings(self, specification: Specification) -> ClaimMapping:
        return self.coverage.map_claims(specification)

    def print_summary(self, writer: TextIO, specification: Specification, name: str):
        """Print coverage summary"""
        pri = specification.cutoff_priority
        if "-" in name:
            name, _, ps= name.rpartition("-")
            pri = int(ps)
        if name == "stats":
            self._print_statistics(writer, specification)
        elif name == "tars":
            self._print_coverage(writer, specification, by_targets=True)
        elif name == "reqs":
            self._print_coverage(writer, specification, by_requirements=True)
        elif not name:
            self._print_coverage(writer, specification)
        else:
            raise Exception(f"No such coverage info '{name}'")

    def _print_coverage(self, writer: TextIO, specification: Specification, by_targets=False,
                        by_requirements=False):
        mapping = self._get_mappings(specification)

        def print_status(name: str, status: RequirementStatus) -> str:
            s = ""
            mark = self._status_marker(status.result)
            props = self._list_properties(status)
            s += f"[{mark}] {name} ({status.result.verdict.value})"
            exp = status.result.get_explanation()
            lines = "\n".join(textwrap.wrap(exp, 80, replace_whitespace=False))
            lines = lines.replace("\n", "\n    ")
            if lines:
                s += f"\n    {lines}"
            prop_s = []
            for k, v in props.items():
                prop_s.append(("[x] " if v else "[ ] ") + f"{k}")
            if prop_s:
                s += f"\n    " + " ".join(prop_s)
            return s

        if by_targets:
            targets = sorted(set([r.target_name for r in specification.requirement_map.values()]))
            for tar in targets:
                writer.write(f"== {tar} ==\n")
                requirements = mapping.get_by_requirements()
                for req in specification.list_requirements():
                    if req.target_name != tar:
                        continue
                    name = specification.get_short_info(req) or req.identifier_string(tail_only=True)
                    writer.write(f"=== {name} ===\n")
                    for ent, stat in requirements.get(req, {}).items():
                        s = print_status(f"{ent.long_name()}", stat)
                        writer.write(f"{s}\n")
        elif by_requirements:
            requirements = mapping.get_by_requirements()
            for req in specification.list_requirements():
                name = specification.get_short_info(req) or req.identifier_string(tail_only=True)
                if req.target_name:
                    name += f"|{req.target_name}"
                writer.write(f"== {name} ==\n")
                for ent, stat in requirements.get(req, {}).items():
                    name = ent.long_name()
                    s = print_status(name, stat)
                    writer.write(f"{s}\n")
        else:
            sections = mapping.get_entities_by_sections()
            for sec, ents in sections.items():
                writer.write(f"== {sec} ===\n")
                for entity, rs in ents.items():
                    writer.write(f"{entity.long_name()}\n")
                    for req, stat in rs.items():
                        name = specification.get_short_info(req) or req.identifier_string(tail_only=True)
                        if req.target_name:
                            name += f"|{req.target_name}"
                        s = print_status(name, stat)
                        writer.write(f"{s}\n")

    def _print_statistics(self, writer: TextIO, specification: Specification):
        mapping = self._get_mappings(specification)
        requirements = mapping.get_by_requirements()

        target_verdicts: Dict[str, Tuple[int, int]] = {}
        target_reqs: Dict[str, Tuple[int, int]] = {}

        for req in specification.list_requirements():
            er = requirements.get(req, {})
            all_c = len([s for s in er.values() if s.result.verdict != Verdict.IGNORE])
            pass_c = len([s for s in er.values() if s.result.verdict == Verdict.PASS])

            if all_c == 0:
                continue  # no requirements

            target = req.target_name
            old_verdicts = target_verdicts.get(target, (0, 0))
            target_verdicts[target] = (old_verdicts[0] + all_c, old_verdicts[1] + pass_c)
            old_reqs = target_reqs.get(target, (0, 0))
            target_reqs[target] = (old_reqs[0] + 1, old_reqs[1] + (1 if pass_c == all_c else 0))

            s = specification.get_short_info(req) or req.identifier_string(tail_only=True)
            s = f"{s:<40}"
            s += f" {pass_c:>3}/{all_c:<3}"
            props = set()
            for st in er.values():
                props.update(self._list_properties(st).keys())
            s += " " + ", ".join(sorted([p.get_name() for p in props]))
            writer.write(f"{s}\n")

        # group by targets?
        use_targets = any([r.target_name for r in specification.requirement_map.values()])
        if use_targets:
            writer.write("\n== Targets ==\n")
            for t, (all, passed) in target_verdicts.items():
                r_all, r_pass = target_reqs[t]
                writer.write(f"{t:<40} {passed:>3}/{all:<3} pass/reqs={r_pass}/{r_all}\n")

    def _status_marker(cls, status: Optional[ClaimStatus]) -> str:
        if status is None or status.verdict == Verdict.INCON:
            return " "
        if status.verdict == Verdict.IGNORE:
            if status.authority in {ClaimAuthority.MODEL, ClaimAuthority.TOOL}:
                return "-"
            return "."
        if status.verdict == Verdict.PASS:
            if status.authority in {ClaimAuthority.MODEL, ClaimAuthority.TOOL}:
                return "X"
            return "x"
        raise Exception(f"Unknown verdict {status.verdict}")

    @classmethod
    def _light(self, verdict: Verdict) -> str:
        """Verdict traffic light"""
        if verdict in {Verdict.IGNORE, Verdict.INCON}:
            return "yellow"
        if verdict == Verdict.PASS:
            return "green"
        return "red"

    @classmethod
    def _update_verdict(self, base: Verdict, verdict: Optional[Verdict]) -> Verdict:
        """Update aggregate verdict"""
        if verdict is None:
            return base
        if base == Verdict.INCON or verdict == Verdict.INCON:
            return Verdict.INCON
        else:
            return Verdict.aggregate(base, verdict)

    def _get_properties(self, status: RequirementStatus) -> Dict[PropertyKey, Dict]:
        """Get properties resolved for a claim"""
        r = {}
        for key, ps in status.context.properties.items():
            ent, _ = key
            sources = self.logging.get_property_sources(ent, keys=set(ps.keys()))
            for p, s in sources.items():
                v = ps.get(p)
                r[p] = {
                    "value": True if v else False,  # boolean value
                    "tools": [s.name],  # NOTE: perhaps we have many later
                }
            # show properties without known sources, as well
            for p, v in ps.items():
                if p in sources:
                    continue
                r[p] = {
                    "value": True if v else False,  # boolean value
                    "tools": [],  # no source
                }
        return r

    def _create_coverage(self, specification: Specification) -> Dict:
        """Create coverage information JSON output"""
        root = {
            "specification": specification.specification_id,
            "specification_name": specification.specification_name
        }
        sections = root["sections"] = []

        mapping = self._get_mappings(specification)

        sec_ent: Dict[str, List[Entity]] = {}
        sec_map: Dict[str, Dict[Requirement, Dict[Entity, RequirementStatus]]] = {}
        use_targets = False
        for sec, reqs in mapping.get_entities_by_sections().items():
            cols = sec_ent[sec] = []
            r_map = sec_map[sec] = {}
            for ent, stat in reqs.items():
                cols.append(ent)
                for req, st in stat.items():
                    use_targets = use_targets or req.target_name
                    r_map.setdefault(req, {})[ent] = st

        req_legend = "Requirements"
        cov_legend = "Coverage items"
        ignore_len_name = f"Tool {Verdict.IGNORE.value}"
        legend = {
            req_legend: "Requirements",
            cov_legend: "Coverage items",
            f"": "Coverage items",
            f"Tool {Verdict.PASS.value}": "Verification pass",
            f"Tool {Verdict.FAIL.value}": "Verification fail",
            ignore_len_name: "Not relevant",
            f"Tool {Verdict.INCON.value}": "Not verified",
            f"Manual {Verdict.PASS.value}": "Explained pass",
            f"Manual {Verdict.IGNORE.value}": "Explained not relevant",
        }
        legend_c = {n: 0 for n in legend.keys()}

        req_count = 0
        for sec_title, req_map in sec_map.items():
            cols: List[Entity] = sec_ent[sec_title]
            col_set = set(cols)
            sec = {
                "name": sec_title,
            }
            sec_cols = sec["columns"] = []
            for c in cols:
                sec_cols.append({"name": c.long_name()})

            def status_data(status: Optional[ClaimStatus]) -> Tuple[str, Verdict]:
                if status:
                    # authority is manual or non-manual (tool)
                    aut = status.authority.value if status.authority == ClaimAuthority.MANUAL \
                        else ClaimAuthority.TOOL.value
                    verdict = status.verdict
                else:
                    # location is not relevant
                    aut = ClaimAuthority.TOOL.value  # nothing defined
                    verdict = Verdict.IGNORE
                return aut, verdict

            req_sorter = specification.get_sorting_key()

            sec_verdict = Verdict.PASS  # section verdict
            col_verdict = [Verdict.PASS] * len(cols)  # column (concept) verdicts
            rows = sec["rows"] = []
            for req, req_stats in sorted(req_map.items(), key=lambda kv: req_sorter(kv[0])):
                if req.priority < specification.cutoff_priority:
                    continue  # quick hack
                if not col_set.intersection(req_stats.keys()):
                    continue
                req_count += 1
                spec, ide = req.identifier
                row_data = {
                    "spec": spec,
                    "id": ide,
                    "text": req.get_text(with_identifier=False),
                    "target": req.target_name,
                }
                s_info = specification.get_short_info(req)
                row_data["short"] = s_info or ide
                col_data = row_data["columns"] = []
                row_verdict = Verdict.PASS
                for ci, c in enumerate(cols):
                    req_stat = req_stats.get(c)
                    props = self._get_properties(req_stat) if req_stat else {}
                    status = req_stat.result if req_stat else None
                    aut, verdict = status_data(status)
                    state_name = f"{aut} {verdict.value}"
                    break_d = []
                    if status:
                        for ss in status.aggregate_of:
                            ss_aut, ss_verdict = status_data(ss)
                            ss_name = f"{ss_aut} {ss_verdict.value}"
                            break_d.append(ss_name)
                    if not break_d:
                        break_d.append(state_name)
                    legend_c[state_name] = legend_c.get(state_name, 0) + 1
                    flags = set()
                    if verdict != Verdict.IGNORE:
                        flags = Properties.get_flags(props)
                    ci_data = {
                        "name": c.long_name(),
                        "state_name": state_name,
                        "verdict": verdict.value,
                        "light": self._light(verdict),
                        "description":
                            "Not a relevant requirement here" if status is None else status.get_explanation(),
                        "checks": break_d,
                        "flags": sorted(flags),
                        "properties": {f"{k}": v for k, v in props.items()},
                    }
                    col_data.append(ci_data)
                    sec_verdict = self._update_verdict(sec_verdict, verdict)
                    row_verdict = self._update_verdict(row_verdict, verdict)
                    col_verdict[ci] = self._update_verdict(col_verdict[ci], verdict)
                row_data["row_verdict"] = row_verdict.value
                row_data["row_light"] = self._light(row_verdict)
                rows.append(row_data)
            # update column data
            for ci, cv in enumerate(col_verdict):
                sec_cols[ci]["column_verdict"] = cv.value
                sec_cols[ci]["column_light"] = self._light(cv)
            sections.append(sec)
            sec["section_verdict"] = sec_verdict.value
            sec["section_light"] = self._light(sec_verdict)

        legend_c[req_legend] = req_count
        legend_c[cov_legend] = sum([s for n, s in legend_c.items() if n != ignore_len_name])
        leg = root["legend"] = {}
        for leg_name, leg_c in legend_c.items():
            leg[leg_name] = {
                "state_name": leg_name,
                "count": leg_c,
                "description": legend.get(leg_name, "")
            }
        root["use_targets"] = bool(use_targets)
        return root

    def json(self, specification: Specification) -> Dict:
        """Give JSON tabular output"""
        return self._create_coverage(specification)
