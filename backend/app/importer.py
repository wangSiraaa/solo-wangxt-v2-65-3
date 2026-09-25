"""
FRR prefix-list text importer — parsing with source fidelity.

The parser is deliberately *lossless*: every input line is classified and
kept (rules, comments, blank lines, description lines and directives we do
not understand), each with its original 1-based line number and raw text.
Nothing is silently dropped, so a draft can always be audited against the
file the network team uploaded.

Recognized grammar (FRR / vtysh):

    ip  prefix-list NAME seq N permit|deny PREFIX [ge X] [le Y]
    ipv6 prefix-list NAME seq N permit|deny PREFIX [ge X] [le Y]
    ip|ipv6 prefix-list NAME description TEXT
    ! comment            (# also accepted)

Semantics notes:

* `seq` may be omitted; FRR then auto-assigns in steps of 5.  We reproduce
  that (per list) and flag it with an `auto-seq` info diagnostic.
* One file may carry several lists, and both address families — drafts are
  keyed by (list name, family keyword), so a dual-stack file yields one
  draft per list.  A *line* whose prefix family contradicts its keyword
  (`ip prefix-list ... 2001:db8::/32`) is a `family-mismatch` error.
* ge/le windows are validated by the engine Rule itself, so the importer
  can never disagree with the simulator about what is legal.

Diagnostics are structured ({code, severity, message}) so the API/UI can
explain each category separately:
    duplicate-seq   (error)   same seq twice in one list
    family-mismatch (error)   prefix family != ip/ipv6 keyword
    bad-ge-le       (error)   illegal ge/le window (engine message attached)
    bad-prefix      (error)   unparseable / host-bits-set prefix
    bad-seq         (error)   seq not an integer in 1..4294967295
    bad-action      (error)   action token is not permit/deny
    unexpected-token(error)   trailing garbage after a rule
    missing-default (warning) file carries no default action; the implicit
                              default applies and must be confirmed
    unparsed        (warning) directive we do not understand (preserved)
    auto-seq        (info)    seq assigned automatically, FRR style
    empty-list      (error)   the list ended up with no usable rule
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .engine import Action, PolicyError, Rule as EngineRule

SEVERITY_ERROR = "error"
SEVERITY_WARNING = "warning"
SEVERITY_INFO = "info"

SEQ_MIN, SEQ_MAX = 1, 4294967295
AUTO_SEQ_STEP = 5          # FRR assigns 5, 10, 15, ... when seq is omitted


@dataclass
class Diagnostic:
    code: str
    severity: str
    message: str

    def to_dict(self) -> dict:
        return {"code": self.code, "severity": self.severity,
                "message": self.message}


@dataclass
class ParsedLine:
    line_no: int
    raw: str
    kind: str                       # rule|comment|blank|description|unparsed
    list_name: Optional[str] = None
    keyword_family: Optional[int] = None     # 4/6 from the ip/ipv6 keyword
    seq: Optional[int] = None
    action: Optional[str] = None
    prefix: Optional[str] = None             # canonicalized when valid
    ge: Optional[int] = None
    le: Optional[int] = None
    diagnostics: List[Diagnostic] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not any(d.severity == SEVERITY_ERROR for d in self.diagnostics)

    def to_dict(self) -> dict:
        return {
            "line_no": self.line_no, "raw": self.raw, "kind": self.kind,
            "list_name": self.list_name, "keyword_family": self.keyword_family,
            "seq": self.seq, "action": self.action, "prefix": self.prefix,
            "ge": self.ge, "le": self.le,
            "diagnostics": [d.to_dict() for d in self.diagnostics],
        }


@dataclass
class DraftSpec:
    """One parsed prefix-list (name + address family) inside a file."""
    name: str
    family: int
    rules: List[dict] = field(default_factory=list)   # normalized rule dicts
    diagnostics: List[Diagnostic] = field(default_factory=list)


@dataclass
class ParseResult:
    lines: List[ParsedLine]
    drafts: List[DraftSpec]

    @staticmethod
    def content_hash(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()


_HEAD_RE = re.compile(r"^(ip|ipv6)\s+prefix-list\s+(?P<name>\S+)\s*(?P<rest>.*)$")


def _diag(code: str, severity: str, message: str) -> Diagnostic:
    return Diagnostic(code=code, severity=severity, message=message)


def _parse_rule_body(line: ParsedLine, rest: str,
                     auto_seq: int) -> None:
    """Fill a rule-kind ParsedLine from the tokens after the list name."""
    tokens = rest.split()
    i = 0
    # ---- optional explicit seq ----
    if i < len(tokens) and tokens[i] == "seq":
        if i + 1 >= len(tokens):
            line.diagnostics.append(_diag(
                "bad-seq", SEVERITY_ERROR, "seq 关键字后缺少序号"))
            return
        try:
            seq = int(tokens[i + 1])
            if not (SEQ_MIN <= seq <= SEQ_MAX):
                raise ValueError
            line.seq = seq
        except ValueError:
            line.diagnostics.append(_diag(
                "bad-seq", SEVERITY_ERROR,
                f"序号 {tokens[i + 1]!r} 非法：须为 {SEQ_MIN}..{SEQ_MAX} 的整数"))
            return
        i += 2
    else:
        line.seq = auto_seq
        line.diagnostics.append(_diag(
            "auto-seq", SEVERITY_INFO,
            f"未写 seq，按 FRR 惯例自动编为 {auto_seq}"))

    # ---- action ----
    if i >= len(tokens):
        line.diagnostics.append(_diag(
            "bad-action", SEVERITY_ERROR, "缺少 permit/deny 动作"))
        return
    if tokens[i] not in ("permit", "deny"):
        line.diagnostics.append(_diag(
            "bad-action", SEVERITY_ERROR,
            f"动作 {tokens[i]!r} 无法识别：仅支持 permit/deny"))
        return
    line.action = tokens[i]
    i += 1

    # ---- prefix ----
    if i >= len(tokens):
        line.diagnostics.append(_diag(
            "bad-prefix", SEVERITY_ERROR, "缺少前缀"))
        return
    raw_prefix = tokens[i]
    i += 1

    # ---- ge / le pairs (order-tolerant) ----
    ge: Optional[int] = None
    le: Optional[int] = None
    while i < len(tokens):
        tok = tokens[i]
        if tok in ("ge", "le") and i + 1 < len(tokens):
            try:
                val = int(tokens[i + 1])
            except ValueError:
                line.diagnostics.append(_diag(
                    "bad-ge-le", SEVERITY_ERROR,
                    f"{tok} 的值 {tokens[i + 1]!r} 不是整数"))
                return
            if tok == "ge":
                ge = val
            else:
                le = val
            i += 2
        else:
            line.diagnostics.append(_diag(
                "unexpected-token", SEVERITY_ERROR,
                f"无法识别的附加 token {tok!r}（该行其余部分已保留原文）"))
            return
    line.ge, line.le = ge, le

    # ---- prefix validity + family agreement, via the engine itself ----
    try:
        rule = EngineRule(seq=line.seq, prefix=raw_prefix,
                          action=Action(line.action), ge=ge, le=le)
    except PolicyError as e:
        line.prefix = raw_prefix
        line.diagnostics.append(_diag(
            "bad-ge-le", SEVERITY_ERROR, f"ge/le 范围非法：{e}"))
        return
    except ValueError as e:
        line.prefix = raw_prefix
        line.diagnostics.append(_diag(
            "bad-prefix", SEVERITY_ERROR, f"前缀非法：{e}"))
        return
    line.prefix = rule.prefix                      # canonical form
    if rule.family != line.keyword_family:
        line.diagnostics.append(_diag(
            "family-mismatch", SEVERITY_ERROR,
            f"地址族混用：关键字 ip{'v6' if line.keyword_family == 6 else ''} "
            f"prefix-list 是 IPv{line.keyword_family}，但前缀 {rule.prefix} "
            f"是 IPv{rule.family}"))


def parse_config(text: str) -> ParseResult:
    """Parse FRR config text into fidelity-preserving lines + list drafts."""
    lines: List[ParsedLine] = []
    # insertion-ordered drafts keyed by (name, family)
    drafts: Dict[Tuple[str, int], DraftSpec] = {}
    last_seq: Dict[Tuple[str, int], int] = {}

    for line_no, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if not stripped:
            lines.append(ParsedLine(line_no=line_no, raw=raw, kind="blank"))
            continue
        if stripped.startswith("!") or stripped.startswith("#"):
            lines.append(ParsedLine(line_no=line_no, raw=raw, kind="comment"))
            continue

        m = _HEAD_RE.match(stripped)
        if not m:
            lines.append(ParsedLine(
                line_no=line_no, raw=raw, kind="unparsed",
                diagnostics=[_diag(
                    "unparsed", SEVERITY_WARNING,
                    "无法识别的指令：原样保留，不会进入草稿规则")]))
            continue

        name = m.group("name")
        family = 6 if m.group(1) == "ipv6" else 4
        rest = m.group("rest").strip()

        if rest.startswith("description"):
            lines.append(ParsedLine(
                line_no=line_no, raw=raw, kind="description",
                list_name=name, keyword_family=family))
            continue

        key = (name, family)
        line = ParsedLine(line_no=line_no, raw=raw, kind="rule",
                          list_name=name, keyword_family=family)
        nxt = last_seq.get(key, 0) + AUTO_SEQ_STEP
        _parse_rule_body(line, rest, auto_seq=nxt)
        lines.append(line)

        draft = drafts.setdefault(key, DraftSpec(name=name, family=family))
        if line.ok and line.action is not None and line.prefix is not None:
            draft.rules.append({
                "seq": line.seq, "prefix": line.prefix, "action": line.action,
                "ge": line.ge, "le": line.le,
                "remark": f"imported line {line_no}",
            })
            last_seq[key] = line.seq
        elif line.seq is not None:
            # keep the auto-seq cadence aligned with what FRR would do even
            # when this particular line is broken
            last_seq[key] = line.seq

    # ---- list-level diagnostics ----
    for draft in drafts.values():
        seqs: Dict[int, List[int]] = {}
        for ln in lines:
            if (ln.kind == "rule" and ln.list_name == draft.name
                    and ln.keyword_family == draft.family and ln.seq is not None):
                seqs.setdefault(ln.seq, []).append(ln.line_no)
        for seq, nos in sorted(seqs.items()):
            if len(nos) > 1:
                draft.diagnostics.append(_diag(
                    "duplicate-seq", SEVERITY_ERROR,
                    f"序号重复：seq {seq} 出现于第 "
                    f"{', '.join(map(str, nos))} 行；首条匹配语义要求序号唯一"))
        if not draft.rules:
            draft.diagnostics.append(_diag(
                "empty-list", SEVERITY_ERROR,
                "该列表没有可用规则（全部解析失败或只有注释）；"
                "空 prefix-list 在 FRR 中等价于全部放行，拒绝导入"))
        draft.diagnostics.append(_diag(
            "missing-default", SEVERITY_WARNING,
            "文件未携带默认行为：未命中任何条目时将按隐式默认动作处理，"
            "采纳前必须显式确认 default_action"))
        draft.rules.sort(key=lambda r: r["seq"])

    return ParseResult(lines=lines, drafts=list(drafts.values()))
