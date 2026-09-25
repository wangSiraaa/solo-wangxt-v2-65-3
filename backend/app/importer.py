"""
Source-fidelity parser for FRRouting `ip/ipv6 prefix-list` configuration text.

Design goals
------------
* **Fidelity**: every input line is preserved verbatim with its original 1-based
  line number.  Comments (``!`` / ``#``), blank lines and directives we do not
  understand are kept as first-class lines, never silently dropped.
* **Isolation**: parsing produces *drafts* (one per ``(list-name, family)``)
  plus typed diagnostics.  Nothing here touches the mainline policy tables.
* **Explainability**: each problem gets its own diagnostic kind so the UI can
  explain them separately:
      - ``duplicate_seq``   same seq twice inside one list (error)
      - ``mixed_family``    v4 prefix under `ipv6` keyword or vice versa (error)
      - ``invalid_range``   illegal ge/le window (error)
      - ``missing_default`` no catch-all entry; implicit default applies (warning)
      - ``parse_error``     malformed prefix-list line (error)
      - ``unrecognized``    directive outside the prefix-list grammar (warning)
      - ``seq_assigned``    missing seq auto-numbered FRR-style, +5 (info)

Lines carrying an *error* are excluded from the draft's candidate rules; the
import can only be adopted once every error diagnostic has been consciously
resolved (dropped) by the operator — a draft therefore never half-applies.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from .engine import MAXLEN, Action, PolicyError
from .engine import Rule as EngineRule

# diagnostic severities
ERROR = "error"
WARNING = "warning"
INFO = "info"

# line kinds
RULE = "rule"
DESCRIPTION = "description"
COMMENT = "comment"
BLANK = "blank"
UNRECOGNIZED = "unrecognized"

MAX_SEQ = 4294967295


@dataclass
class ParsedLine:
    line_no: int
    raw: str
    kind: str
    list_name: Optional[str] = None
    family: Optional[int] = None
    seq: Optional[int] = None
    prefix: Optional[str] = None
    action: Optional[str] = None
    ge: Optional[int] = None
    le: Optional[int] = None
    description: Optional[str] = None
    error_kind: Optional[str] = None      # parse_error / mixed_family / invalid_range
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "line_no": self.line_no, "raw": self.raw, "kind": self.kind,
            "list_name": self.list_name, "family": self.family,
            "seq": self.seq, "prefix": self.prefix, "action": self.action,
            "ge": self.ge, "le": self.le, "description": self.description,
            "error_kind": self.error_kind, "error": self.error,
        }


@dataclass
class DiagnosticSpec:
    severity: str
    kind: str
    message: str
    line_no: Optional[int] = None
    list_name: Optional[str] = None
    family: Optional[int] = None


@dataclass
class DraftSpec:
    name: str
    family: int
    description: str = ""
    default_action: str = "deny"
    rules: List[dict] = field(default_factory=list)   # normalized rule dicts


@dataclass
class ParseResult:
    lines: List[ParsedLine]
    drafts: List[DraftSpec]
    diagnostics: List[DiagnosticSpec]


# ---------------------------------------------------------------------------
# single-line parsing
# ---------------------------------------------------------------------------

def _parse_rule_body(line: ParsedLine, tokens: List[str]) -> None:
    """Parse the part after `ip|ipv6 prefix-list NAME`.  Fills `line` in place;
    on any problem sets error_kind/error instead of raising."""
    family = 4 if tokens[0] == "ip" else 6
    line.family = family
    line.list_name = tokens[2]
    rest = tokens[3:]

    if rest and rest[0] == "description":
        line.kind = DESCRIPTION
        line.description = " ".join(rest[1:]).strip().strip('"')
        return

    line.kind = RULE
    idx = 0
    seq: Optional[int] = None
    if idx < len(rest) and rest[idx] == "seq":
        if idx + 1 >= len(rest) or not rest[idx + 1].isdigit():
            line.error_kind = "parse_error"
            line.error = "seq 关键字后缺少有效序号"
            return
        seq = int(rest[idx + 1])
        if not (1 <= seq <= MAX_SEQ):
            line.error_kind = "parse_error"
            line.error = f"序号 {seq} 超出范围 (1..{MAX_SEQ})"
            return
        idx += 2
    line.seq = seq

    if idx >= len(rest) or rest[idx] not in ("permit", "deny"):
        line.error_kind = "parse_error"
        line.error = "缺少 permit/deny 动作"
        return
    line.action = rest[idx]
    idx += 1

    if idx >= len(rest):
        line.error_kind = "parse_error"
        line.error = "缺少前缀"
        return
    raw_prefix = rest[idx]
    idx += 1

    ge = le = None
    while idx < len(rest):
        key = rest[idx]
        if key not in ("ge", "le"):
            line.error_kind = "parse_error"
            line.error = f"无法识别的标记 {key!r}（仅支持 ge/le）"
            return
        if idx + 1 >= len(rest) or not rest[idx + 1].isdigit():
            line.error_kind = "parse_error"
            line.error = f"{key} 关键字后缺少有效数值"
            return
        val = int(rest[idx + 1])
        if key == "ge":
            if ge is not None:
                line.error_kind = "parse_error"
                line.error = "ge 重复出现"
                return
            ge = val
        else:
            if le is not None:
                line.error_kind = "parse_error"
                line.error = "le 重复出现"
                return
            le = val
        idx += 2
    line.ge, line.le = ge, le

    # prefix + ge/le window: delegate to the engine's own Rule so shorthand
    # ("10/8" -> "10.0.0.0/8") and range checks behave exactly like the editor
    try:
        rule = EngineRule(seq=seq or 0, prefix=raw_prefix,
                          action=Action(line.action), ge=ge, le=le)
    except PolicyError as e:
        line.error_kind = "invalid_range"
        line.error = f"非法 ge/le 范围：{e}"
        return
    except ValueError as e:
        line.error_kind = "parse_error"
        line.error = f"前缀 {raw_prefix!r} 非法：{e}"
        return
    if rule.family != family:
        line.prefix = rule.prefix
        line.error_kind = "mixed_family"
        line.error = (
            f"指令使用 ipv{family} 关键字，但前缀 {rule.prefix} 是 "
            f"IPv{rule.family}；地址族混用，本工作台严格隔离 IPv4/IPv6"
        )
        return
    line.prefix = rule.prefix


def parse_line(line_no: int, raw: str) -> ParsedLine:
    stripped = raw.strip()
    if not stripped:
        return ParsedLine(line_no=line_no, raw=raw, kind=BLANK)
    if stripped.startswith("!") or stripped.startswith("#"):
        return ParsedLine(line_no=line_no, raw=raw, kind=COMMENT)

    tokens = stripped.split()
    line = ParsedLine(line_no=line_no, raw=raw, kind=UNRECOGNIZED)
    if (len(tokens) >= 3 and tokens[0] in ("ip", "ipv6")
            and tokens[1] == "prefix-list"):
        _parse_rule_body(line, tokens)
    return line


# ---------------------------------------------------------------------------
# whole-file parsing
# ---------------------------------------------------------------------------

def parse_config(text: str) -> ParseResult:
    lines = [parse_line(i + 1, raw) for i, raw in enumerate(text.splitlines())]
    diagnostics: List[DiagnosticSpec] = []

    # per-line errors -> diagnostics; errored lines never reach a draft
    for ln in lines:
        if ln.kind == RULE and ln.error_kind:
            diagnostics.append(DiagnosticSpec(
                severity=ERROR, kind=ln.error_kind, line_no=ln.line_no,
                list_name=ln.list_name, family=ln.family, message=ln.error or ""))
        elif ln.kind == UNRECOGNIZED:
            diagnostics.append(DiagnosticSpec(
                severity=WARNING, kind="unrecognized", line_no=ln.line_no,
                message="无法识别的指令，已原样保留，不参与导入"))

    # group candidate rule lines by (list name, keyword family)
    groups: dict[tuple[str, int], List[ParsedLine]] = {}
    for ln in lines:
        if ln.kind == RULE and ln.error_kind is None:
            groups.setdefault((ln.list_name, ln.family), []).append(ln)

    drafts: List[DraftSpec] = []
    for (name, family), members in groups.items():
        # auto-number missing seqs FRR-style (previous + 5)
        last_seq = 0
        for ln in members:
            if ln.seq is None:
                ln.seq = last_seq + 5
                diagnostics.append(DiagnosticSpec(
                    severity=INFO, kind="seq_assigned", line_no=ln.line_no,
                    list_name=name, family=family,
                    message=f"行缺少 seq，按 FRR 惯例自动编号为 {ln.seq}"))
            last_seq = ln.seq

        # duplicate seq: first occurrence wins, later ones become errors
        seen: dict[int, int] = {}
        survivors: List[ParsedLine] = []
        for ln in members:
            if ln.seq in seen:
                ln.error_kind = "duplicate_seq"
                ln.error = (
                    f"序号 {ln.seq} 与第 {seen[ln.seq]} 行重复；首条匹配语义下"
                    "重复序号会使配置被拒绝或行为不确定，该行未纳入草稿")
                diagnostics.append(DiagnosticSpec(
                    severity=ERROR, kind="duplicate_seq", line_no=ln.line_no,
                    list_name=name, family=family, message=ln.error))
            else:
                seen[ln.seq] = ln.line_no
                survivors.append(ln)

        rules = [
            EngineRule(seq=ln.seq, prefix=ln.prefix, action=Action(ln.action),
                       ge=ln.ge, le=ln.le)
            for ln in survivors
        ]
        rules.sort(key=lambda r: r.seq)

        desc = " ".join(ln.description for ln in lines
                        if ln.kind == DESCRIPTION and ln.list_name == name
                        and ln.family == family and ln.description)
        draft = DraftSpec(
            name=name, family=family, description=desc,
            rules=[{"seq": r.seq, "prefix": r.prefix, "action": r.action.value,
                    "ge": r.ge, "le": r.le, "remark": ""} for r in rules],
        )
        drafts.append(draft)

        # default behavior: is there a catch-all (matches every prefix)?
        maxlen = MAXLEN[family]
        catch_all = any(r.min_len == 0 and r.max_len == maxlen for r in rules)
        if not catch_all:
            diagnostics.append(DiagnosticSpec(
                severity=WARNING, kind="missing_default",
                list_name=name, family=family,
                message=(
                    f"列表 {name} (IPv{family}) 没有兜底条目"
                    f"（如 {'0.0.0.0/0 le 32' if family == 4 else '::/0 le 128'}）；"
                    "未命中的前缀将落入隐式默认动作。采纳时默认动作沿用目标策略的"
                    "当前值（新策略则为 deny），也可在采纳时显式覆盖")))

    drafts.sort(key=lambda d: (d.name, d.family))
    return ParseResult(lines=lines, drafts=drafts, diagnostics=diagnostics)
