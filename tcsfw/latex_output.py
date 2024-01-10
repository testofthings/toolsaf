import logging
from typing import TextIO, Dict, Tuple, List, Set, Optional

from tcsfw.claim_coverage import RequirementClaimMapper
from tcsfw.etsi_ts_103_701 import IXIT
from tcsfw.model import IoTSystem
from tcsfw.property import Properties, PropertyKey
from tcsfw.requirement import Specification


def bf(value: str) -> str:
    """Latex bf"""
    return f"{{\\bf {value}}}"


class LaTeXGenerator:
    def __init__(self, system: IoTSystem, specification: Specification, coverage: RequirementClaimMapper):
        self.logger = logging.getLogger("report")
        self.system = system
        self.specification = specification
        self.coverage = coverage
        self.mapping = self.coverage.map_claims(specification)

        basic_tools = "Basic tools"
        net = "Network scan and capture"
        protocol = "Protocol-specific"
        web_avail = "Web page availability"

        advanced_tools = "Advanced tools"
        mitm = "MITM"
        input_validation = "Input validation"
        password_crack = "Password brute-forcing"
        net_power = "Network/power switch"

        custom_tools = "Custom tools"
        # setup = "Product setup"  # integrated to ui
        access_control = "Access control"
        code_check = "Code analysis"
        functional = "Functional"
        internal = "Internal properties"
        update_miuse = "Unauthorized update"

        manual = "UI tests"
        self.content = "Document review"
        self.ui = "UI usage"
        self.physical = "Physical inspection"

        self.targets = {
            IXIT.AuthMech.name: {net: 2, self.ui: 3, functional: 2, password_crack: 1, protocol: 3},
            IXIT.UserInfo.name: {web_avail: 3, self.ui: 4, self.content: 11},
            IXIT.UpdMech.name: {protocol: 3, net: 1, update_miuse: 3, mitm: 1, self.ui: 3},
            IXIT.ReplSup.name: {web_avail: 2, self.content: 3, net_power: 1, self.physical: 1, self.ui: 1, functional: 2},
            IXIT.SecParam.name: {internal: 3},
            IXIT.ComMech.name: {protocol: 3, net: 1},
            IXIT.NetSecImpl.name: {code_check: 3},
            IXIT.SoftServ.name: {access_control: 2, protocol: 1},
            IXIT.Intf.name: {net: 7, self.physical: 2},
            IXIT.SecBoot.name: {internal: 1, self.ui: 1, net: 1},
            IXIT.ExtSens.name: {web_avail: 1, self.content: 1, self.physical: 1},
            IXIT.ResMech.name: {net_power: 3, functional: 2},
            IXIT.TelData.name: {self.content: 2, functional: 2},
            IXIT.DelFunc.name: {self.ui: 11},
            IXIT.UserDec.name: {self.ui: 5},
            IXIT.UserIntf.name: {self.content: 1},
            IXIT.ExtAPI.name: {net: 1},
            IXIT.InpVal.name: {input_validation: 1},
        }
        self.categories = {
            basic_tools: [net, protocol, web_avail],
            advanced_tools: [mitm, input_validation, password_crack, code_check, net_power],
            custom_tools: [access_control, functional, update_miuse, internal],
            manual: [self.content, self.ui, self.physical],
        }


    def generate(self, writer: TextIO, name: str):
        """Generate something"""
        if name == "targets":
            self._test_targets(writer)
        elif name == "tools":
            self._tool_categories(writer)
        elif name == "annotations":
            self._target_annotations(writer)
        else:
            raise Exception(f"Do not know how to generate '{name}'")

    def _test_targets(self, writer: TextIO):
        """Target target table"""
        targets: Dict[str, List[int]] = {}
        for r in self.specification.requirement_map.values():
            if r.properties.get(Properties.REVIEW):
                continue  # no in my table
            name = r.selector.get_name()
            v = targets.get(name, [0] * 4)
            if not r.properties.get(Properties.FUNCTIONAL):
                v[0] += 1
            else:
                v[1] += 1
            if r.properties.get(Properties.UI):
                v[2] += 1
            if r.properties.get(Properties.DOCUMENT_CONTENT):
                v[3] += 1
            targets[name] = v

        writer.write(f"{bf('Test target')} & {bf('Conc.')} & {bf('Func.')} & {bf('UI')} & {bf('Cont.')}" + " \\\\\n")
        writer.write("\\hline\n")
        tot = [0] * 4
        for n, v in targets.items():
            vs = " & ".join([f"{vv:>5}" for vv in v])
            writer.write(f"{n:<10} & {vs}" + " \\\\\n")
            writer.write("\\hline\n")
            for i, vv in enumerate(v):
                tot[i] += vv
        vs = " & ".join([f"{vv:>5}" for vv in tot])
        writer.write(f"{bf('Total')} & {vs}" + " \\\\\n")
        writer.write("\\hline\n")

    def _tool_categories(self, writer: TextIO):
        """Tool categories table"""
        counts: Dict[Tuple[str, str], int] = {}
        target_counts: Dict[str, int] = {}
        tool_counts: Dict[str, int] = {}
        for tar, cats in self.targets.items():
            cc = 0
            for t, c in cats.items():
                counts[tar, t] = counts.get((tar, t), 0) + c
                target_counts[tar] = target_counts.get(tar, 0) + c
                tool_counts[t] = tool_counts.get(t, 0) + c
                cc += c
            # writer.write(f"% {tar} {cc} units\n")
        tool_c = sum(tool_counts.values())

        cat_counts: Dict[str, int] = {}
        for cat, tools in self.categories.items():
            cat_c = 0
            for t in tools:
                cat_c += tool_counts[t]
            cat_counts[cat] = cat_c

        writer.write(r"\begin{tabular}{|l|" + "c|" * len(self.targets) + "r|}\n")
        writer.write("\\hline\n")

        gray = r"\Hl"  # command defined in LaTeX sources

        # Headers
        hds = ["Test target"]
        for i, h in enumerate(self.targets.keys()):
            color = gray if i % 2 == 0 else ""
            s = color + r" \rotatebox{90}{" + h + "}"
            if i < len(self.targets) - 1:
                s = r" \multicolumn{1}{c}{" + s + "}"
            hds.append(s)
        hds.append("Share")
        hds_s = " & ".join(hds)
        writer.write(f"{hds_s}" + " \\\\\n")
        writer.write("\\hline\n")

        writer.write(r"{\bf Product security tests}")
        writer.write(r" $\mathbf{T_P}$")
        for i, tar in enumerate(self.targets.keys()):
            c = target_counts.get(tar)
            color = gray if i % 2 == 0 else ""
            writer.write(f" & {color} {c}")
        share = bf(f"{sum(target_counts.values()) / tool_c * 100:.0f}\\%")
        writer.write(f" & {share} \\\\\n")
        writer.write("\\hline\n")

        writer.write(bf(r"{\bf Security perimeter tests}"))
        writer.write(r" $\mathbf{T_S}$")
        excl_manual = 0
        for i, tar in enumerate(self.targets.keys()):
            c = (target_counts.get(tar) -
                 counts.get((tar, self.ui), 0) - counts.get((tar, self.content), 0) -
                 counts.get((tar, self.physical), 0))
            excl_manual += c
            color = gray if i % 2 == 0 else ""
            cs = f" {c}" if c else ""
            writer.write(f" & {color} {cs}")
        share = bf(f"{excl_manual / tool_c * 100:.0f}\\%")
        writer.write(f" & {share} \\\\\n")

        for cat_n, tools in self.categories.items():
            share = f"{cat_counts[cat_n] / tool_c * 100:.0f}\\%"
            ui_row = "UI" in cat_n
            writer.write("\\hline\n")
            cols = ""
            for i in range(0, len(self.targets)):
                cols += f" & {gray} " if i % 2 == 0 else " & "
            if ui_row:
                cat_n = cat_n + r" $\mathbf{T_U}$"
                share = bf(share)
            writer.write(f"{bf(cat_n)}{cols} & {share} " + " \\\\ \n")
            # cols = f"\\multicolumn{{{1 + len(targets)}}}{{|l|}}{{{bf(cat_n)}}}"
            # writer.write(f"{cols} & {share} " + " \\\\ \n")
            for t in tools:
                writer.write(f"\\hline\n")
                writer.write(t)
                for i, tar in enumerate(self.targets.keys()):
                    t_tools = self.targets.get(tar, set())
                    c = counts.get((tar, t))
                    if c is not None:
                        m = f" {c}"
                    else:
                        m = f" x" if t in t_tools else ""
                    color = gray if i % 2 == 0 else ""
                    writer.write(f" & {color} {m}")
                writer.write(" & ")
                writer.write("\\\\\n")
        writer.write("\\hline\n")

        writer.write(f"% Product test units:       {sum(target_counts.values())}\n")
        for cat_n, tools in self.categories.items():
            writer.write(f"% - {cat_n + ':':<23} {cat_counts[cat_n]}\n")
        writer.write(f"% Non-manual test units:    {excl_manual}\n")
        writer.write(f"% + Doc. automation:        {excl_manual + tool_counts[self.content]}\n")
        writer.write(f"% + Doc. + UI automation:   {excl_manual + tool_counts[self.content] + tool_counts[self.ui]}\n")

        writer.write(r"\end{tabular}" + "\n")

    def _target_annotations(self, writer: TextIO):
        mapping = self.coverage.map_claims(self.specification)

        avoid_props = {Properties.UI, Properties.PHYSICAL, Properties.DOCUMENT_CONTENT}
        avoid_prefix = {"check:content:"}

        # filter for paper readability
        def do_filter(p: PropertyKey) -> Optional[PropertyKey]:
            if p in avoid_props:
                return None
            s = p.get_name()
            if any([s.startswith(p) for p in avoid_prefix]):
                return None
            s = p.get_name()
            if s.startswith("check:avail:"):
                return None
            return p

        annotations: Dict[PropertyKey, Dict[str, int]] = {}
        tooled: Set[PropertyKey] = set()
        for req, er in mapping.get_by_requirements().items():
            if req.priority < self.specification.cutoff_priority:
                continue
            target = req.selector.get_name()
            props = set()
            for ent, stat in er.items():
                for ps in stat.context.properties.values():
                    for p, v in ps.items():
                        fs = do_filter(p)
                        if fs:
                            props.add(fs)
                            if v:
                                tooled.add(fs)
            for p in props:
                counts = annotations.setdefault(p, {})
                counts[target] = counts.get(target, 0) + 1

        writer.write(r"\hline" + "\n")
        for ann, targets in sorted(annotations.items()):
            tar_s = []
            for t, c in sorted(targets.items()):
                tar_s.append(f"${t}^{c}$")
            is_tool = ann in tooled

            writer.write(f"% {ann}\n")
            writer.write(f"{ann} ")
            writer.write(f"& \\scriptsize {', '.join(tar_s)} ")
            writer.write(f"& {'TOOLS' if is_tool else ''} ")
            writer.write(r"\\" + "\n")
            writer.write(r"\hline" + "\n")


