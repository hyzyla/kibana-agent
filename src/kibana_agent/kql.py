"""KQL (Kibana Query Language) to Elasticsearch DSL translator.

Implements a recursive-descent parser for KQL and translates the AST to
Elasticsearch Query DSL.

Reference grammar:
  elastic/kibana .../kbn-es-query/src/kuery/grammar/grammar.peggy

Supported syntax:
  field:value            match query
  field:"exact phrase"   match_phrase query
  field:val*             wildcard query
  field:*                exists query
  field > 100            range query (>, >=, <, <=)
  expr1 and expr2        bool filter (implicit AND also supported)
  expr1 or expr2         bool should
  not expr               bool must_not
  (expr)                 grouping
  field:(v1 or v2)       value list
  field:{ subquery }     nested query
  value                  unqualified query_string
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto
from typing import Any


class KQLSyntaxError(Exception):
    """Raised when a KQL query has invalid syntax."""

    def __init__(self, message: str, pos: int) -> None:
        self.pos = pos
        super().__init__(f"{message} (at position {pos})")


class _TT(Enum):
    AND = auto()
    OR = auto()
    NOT = auto()
    COLON = auto()
    LPAREN = auto()
    RPAREN = auto()
    LBRACE = auto()
    RBRACE = auto()
    LT = auto()
    LTE = auto()
    GT = auto()
    GTE = auto()
    LITERAL = auto()
    QUOTED = auto()
    EOF = auto()


@dataclass(frozen=True, slots=True)
class _Token:
    type: _TT
    value: str
    pos: int


_BREAK_CHARS = frozenset(' \t\r\n:(){}><"')


def _tokenize(query: str) -> list[_Token]:
    tokens: list[_Token] = []
    i = 0
    n = len(query)

    single_map = {
        ":": _TT.COLON,
        "(": _TT.LPAREN,
        ")": _TT.RPAREN,
        "{": _TT.LBRACE,
        "}": _TT.RBRACE,
    }

    while i < n:
        ch = query[i]

        if ch in " \t\r\n":
            i += 1
            continue

        if ch == ">" and i + 1 < n and query[i + 1] == "=":
            tokens.append(_Token(_TT.GTE, ">=", i))
            i += 2
            continue
        if ch == "<" and i + 1 < n and query[i + 1] == "=":
            tokens.append(_Token(_TT.LTE, "<=", i))
            i += 2
            continue
        if ch == ">":
            tokens.append(_Token(_TT.GT, ">", i))
            i += 1
            continue
        if ch == "<":
            tokens.append(_Token(_TT.LT, "<", i))
            i += 1
            continue

        if ch in single_map:
            tokens.append(_Token(single_map[ch], ch, i))
            i += 1
            continue

        if ch == '"':
            start = i
            i += 1
            chars: list[str] = []
            while i < n and query[i] != '"':
                if query[i] == "\\" and i + 1 < n:
                    i += 1
                    esc = {"n": "\n", "t": "\t", "r": "\r"}.get(query[i])
                    chars.append(esc if esc else query[i])
                else:
                    chars.append(query[i])
                i += 1
            if i < n:
                i += 1
            tokens.append(_Token(_TT.QUOTED, "".join(chars), start))
            continue

        start = i
        chars = []
        had_escape = False
        while i < n and query[i] not in _BREAK_CHARS:
            if query[i] == "\\" and i + 1 < n:
                i += 1
                chars.append(query[i])
                had_escape = True
            else:
                chars.append(query[i])
            i += 1
        text = "".join(chars)

        if not had_escape:
            lower = text.lower()
            if lower == "and":
                tokens.append(_Token(_TT.AND, text, start))
                continue
            if lower == "or":
                tokens.append(_Token(_TT.OR, text, start))
                continue
            if lower == "not":
                tokens.append(_Token(_TT.NOT, text, start))
                continue

        tokens.append(_Token(_TT.LITERAL, text, start))

    tokens.append(_Token(_TT.EOF, "", n))
    return tokens


@dataclass(frozen=True, slots=True)
class _And:
    left: _Node
    right: _Node


@dataclass(frozen=True, slots=True)
class _Or:
    left: _Node
    right: _Node


@dataclass(frozen=True, slots=True)
class _Not:
    child: _Node


@dataclass(frozen=True, slots=True)
class _FieldMatch:
    field: str
    value: str


@dataclass(frozen=True, slots=True)
class _FieldPhrase:
    field: str
    value: str


@dataclass(frozen=True, slots=True)
class _Exists:
    field: str


@dataclass(frozen=True, slots=True)
class _Wildcard:
    field: str
    pattern: str


@dataclass(frozen=True, slots=True)
class _Range:
    field: str
    op: str
    value: str | int | float


@dataclass(frozen=True, slots=True)
class _Nested:
    field: str
    child: _Node


@dataclass(frozen=True, slots=True)
class _Unqualified:
    value: str


_Node = (
    _And
    | _Or
    | _Not
    | _FieldMatch
    | _FieldPhrase
    | _Exists
    | _Wildcard
    | _Range
    | _Nested
    | _Unqualified
)


_FIELD_TOKEN_TYPES = frozenset({_TT.LITERAL, _TT.NOT, _TT.AND, _TT.OR})
_RANGE_OPS = frozenset({_TT.GT, _TT.GTE, _TT.LT, _TT.LTE})
_EXPRESSION_STARTERS = frozenset({_TT.LITERAL, _TT.QUOTED, _TT.NOT, _TT.LPAREN})


class _Parser:
    def __init__(self, tokens: list[_Token]) -> None:
        self._tokens = tokens
        self._pos = 0

    def _peek(self) -> _Token:
        return self._tokens[self._pos]

    def _advance(self) -> _Token:
        token = self._tokens[self._pos]
        self._pos += 1
        return token

    def _expect(self, tt: _TT) -> _Token:
        token = self._advance()
        if token.type != tt:
            raise KQLSyntaxError(
                f"expected {tt.name}, got {token.type.name} '{token.value}'", token.pos
            )
        return token

    def _lookahead(self) -> _Token:
        idx = self._pos + 1
        return self._tokens[idx] if idx < len(self._tokens) else self._tokens[-1]

    def parse(self) -> _Node:
        if self._peek().type == _TT.EOF:
            raise KQLSyntaxError("empty query", 0)
        node = self._or_query()
        if self._peek().type != _TT.EOF:
            raise KQLSyntaxError(f"unexpected '{self._peek().value}'", self._peek().pos)
        return node

    def _or_query(self) -> _Node:
        left = self._and_query()
        while self._peek().type == _TT.OR:
            self._advance()
            right = self._and_query()
            left = _Or(left, right)
        return left

    def _and_query(self) -> _Node:
        left = self._not_query()
        while True:
            if self._peek().type == _TT.AND:
                self._advance()
                right = self._not_query()
                left = _And(left, right)
            elif self._peek().type in _EXPRESSION_STARTERS and self._peek().type != _TT.OR:
                right = self._not_query()
                left = _And(left, right)
            else:
                break
        return left

    def _not_query(self) -> _Node:
        if self._peek().type == _TT.NOT:
            next_type = self._lookahead().type
            if next_type == _TT.COLON or next_type in _RANGE_OPS:
                return self._expression()
            self._advance()
            return _Not(self._sub_query())
        return self._sub_query()

    def _sub_query(self) -> _Node:
        if self._peek().type == _TT.LPAREN:
            self._advance()
            node = self._or_query()
            self._expect(_TT.RPAREN)
            return node
        return self._expression()

    def _expression(self) -> _Node:
        token = self._peek()

        if token.type in _FIELD_TOKEN_TYPES:
            next_type = self._lookahead().type
            if next_type == _TT.COLON:
                field = self._advance().value
                self._advance()
                return self._field_value(field)
            if next_type in _RANGE_OPS:
                field = self._advance().value
                op = self._advance().value
                value = self._raw_value()
                return _Range(field, op, _coerce_number(value))

        if token.type in (_TT.LITERAL, _TT.QUOTED):
            return _Unqualified(self._advance().value)

        raise KQLSyntaxError(f"unexpected '{token.value}'", token.pos)

    def _field_value(self, field: str) -> _Node:
        token = self._peek()

        if token.type == _TT.LBRACE:
            self._advance()
            node = self._or_query()
            self._expect(_TT.RBRACE)
            return _Nested(field, node)

        if token.type == _TT.LPAREN:
            self._advance()
            node = self._value_list_or(field)
            self._expect(_TT.RPAREN)
            return node

        value, is_quoted = self._value()
        if not is_quoted and value == "*":
            return _Exists(field)
        if not is_quoted and "*" in value:
            return _Wildcard(field, value)
        if is_quoted:
            return _FieldPhrase(field, value)
        return _FieldMatch(field, value)

    def _value_list_or(self, field: str) -> _Node:
        left = self._value_list_and(field)
        while self._peek().type == _TT.OR:
            self._advance()
            right = self._value_list_and(field)
            left = _Or(left, right)
        return left

    def _value_list_and(self, field: str) -> _Node:
        left = self._value_list_not(field)
        while self._peek().type == _TT.AND:
            self._advance()
            right = self._value_list_not(field)
            left = _And(left, right)
        return left

    def _value_list_not(self, field: str) -> _Node:
        if self._peek().type == _TT.NOT:
            self._advance()
            return _Not(self._value_list_item(field))
        return self._value_list_item(field)

    def _value_list_item(self, field: str) -> _Node:
        if self._peek().type == _TT.LPAREN:
            self._advance()
            node = self._value_list_or(field)
            self._expect(_TT.RPAREN)
            return node
        value, is_quoted = self._value()
        if not is_quoted and value == "*":
            return _Exists(field)
        if not is_quoted and "*" in value:
            return _Wildcard(field, value)
        if is_quoted:
            return _FieldPhrase(field, value)
        return _FieldMatch(field, value)

    def _value(self) -> tuple[str, bool]:
        token = self._peek()
        if token.type == _TT.QUOTED:
            self._advance()
            return token.value, True
        if token.type in (_TT.LITERAL, _TT.AND, _TT.OR, _TT.NOT):
            self._advance()
            return token.value, False
        raise KQLSyntaxError(f"expected value, got '{token.value}'", token.pos)

    def _raw_value(self) -> str:
        token = self._peek()
        if token.type in (_TT.QUOTED, _TT.LITERAL):
            self._advance()
            return token.value
        raise KQLSyntaxError(f"expected value, got '{token.value}'", token.pos)


_RANGE_OP_MAP = {">": "gt", ">=": "gte", "<": "lt", "<=": "lte"}


def _coerce_number(value: str) -> str | int | float:
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        return value


def _collect(node: _Node, node_type: type) -> list[_Node]:
    """Flatten chained binary nodes: And(And(a, b), c) → [a, b, c]."""
    if isinstance(node, node_type):
        return _collect(node.left, node_type) + _collect(node.right, node_type)  # type: ignore[union-attr]
    return [node]


def _to_es(node: _Node) -> dict[str, Any]:
    if isinstance(node, _And):
        return {"bool": {"filter": [_to_es(child) for child in _collect(node, _And)]}}

    if isinstance(node, _Or):
        return {
            "bool": {
                "should": [_to_es(child) for child in _collect(node, _Or)],
                "minimum_should_match": 1,
            }
        }

    if isinstance(node, _Not):
        return {"bool": {"must_not": [_to_es(node.child)]}}

    if isinstance(node, _FieldMatch):
        if node.field == "*":
            return {"query_string": {"query": node.value}}
        return {"match": {node.field: node.value}}

    if isinstance(node, _FieldPhrase):
        if node.field == "*":
            return {"query_string": {"query": f'"{node.value}"'}}
        return {"match_phrase": {node.field: node.value}}

    if isinstance(node, _Exists):
        return {"exists": {"field": node.field}}

    if isinstance(node, _Wildcard):
        if node.field == "*":
            return {"query_string": {"query": node.pattern}}
        return {"wildcard": {node.field: {"value": node.pattern}}}

    if isinstance(node, _Range):
        return {"range": {node.field: {_RANGE_OP_MAP[node.op]: node.value}}}

    if isinstance(node, _Nested):
        return {"nested": {"path": node.field, "query": _to_es(node.child)}}

    if isinstance(node, _Unqualified):
        if node.value == "*":
            return {"match_all": {}}
        return {"query_string": {"query": node.value}}

    raise TypeError(f"unknown node: {type(node)}")  # pragma: no cover


def kql_to_es(query: str) -> dict[str, Any]:
    """Parse a KQL query and return an Elasticsearch DSL query dict."""
    tokens = _tokenize(query)
    ast = _Parser(tokens).parse()
    return _to_es(ast)
