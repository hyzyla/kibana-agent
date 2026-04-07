from __future__ import annotations

import pytest

from kibana_agent.kql import KQLSyntaxError, kql_to_es


class TestFieldMatch:
    def test_simple(self) -> None:
        assert kql_to_es("level:ERROR") == {"match": {"level": "ERROR"}}

    def test_dotted_field(self) -> None:
        assert kql_to_es("kubernetes.labels.app:web") == {
            "match": {"kubernetes.labels.app": "web"}
        }

    def test_hyphenated_value(self) -> None:
        assert kql_to_es("app:my-service") == {"match": {"app": "my-service"}}

    def test_wildcard_field(self) -> None:
        assert kql_to_es("*:ERROR") == {"query_string": {"query": "ERROR"}}


class TestFieldPhrase:
    def test_quoted_value(self) -> None:
        assert kql_to_es('level:"error message"') == {
            "match_phrase": {"level": "error message"}
        }

    def test_escape_in_quoted(self) -> None:
        assert kql_to_es('msg:"line1\\nline2"') == {
            "match_phrase": {"msg": "line1\nline2"}
        }

    def test_wildcard_field_quoted(self) -> None:
        assert kql_to_es('*:"exact phrase"') == {
            "query_string": {"query": '"exact phrase"'}
        }


class TestExists:
    def test_star_value(self) -> None:
        assert kql_to_es("level:*") == {"exists": {"field": "level"}}


class TestWildcard:
    def test_trailing_star(self) -> None:
        assert kql_to_es("level:err*") == {"wildcard": {"level": {"value": "err*"}}}

    def test_leading_star(self) -> None:
        assert kql_to_es("msg:*error") == {"wildcard": {"msg": {"value": "*error"}}}

    def test_middle_star(self) -> None:
        assert kql_to_es("path:/api/*/health") == {
            "wildcard": {"path": {"value": "/api/*/health"}}
        }

    def test_wildcard_field_with_wildcard_value(self) -> None:
        assert kql_to_es("*:err*") == {"query_string": {"query": "err*"}}


class TestRange:
    def test_gt_integer(self) -> None:
        assert kql_to_es("bytes > 1000") == {"range": {"bytes": {"gt": 1000}}}

    def test_gte_integer(self) -> None:
        assert kql_to_es("bytes >= 500") == {"range": {"bytes": {"gte": 500}}}

    def test_lt_integer(self) -> None:
        assert kql_to_es("status < 400") == {"range": {"status": {"lt": 400}}}

    def test_lte_float(self) -> None:
        assert kql_to_es("score <= 0.5") == {"range": {"score": {"lte": 0.5}}}

    def test_string_value(self) -> None:
        assert kql_to_es("@timestamp > 2024-01-01") == {
            "range": {"@timestamp": {"gt": "2024-01-01"}}
        }


class TestBooleanOperators:
    def test_and(self) -> None:
        assert kql_to_es("level:ERROR and app:web") == {
            "bool": {"filter": [{"match": {"level": "ERROR"}}, {"match": {"app": "web"}}]}
        }

    def test_or(self) -> None:
        assert kql_to_es("level:ERROR or level:WARN") == {
            "bool": {
                "should": [{"match": {"level": "ERROR"}}, {"match": {"level": "WARN"}}],
                "minimum_should_match": 1,
            }
        }

    def test_not(self) -> None:
        assert kql_to_es("not level:DEBUG") == {
            "bool": {"must_not": [{"match": {"level": "DEBUG"}}]}
        }

    def test_case_insensitive_and(self) -> None:
        assert kql_to_es("level:ERROR AND app:web") == {
            "bool": {"filter": [{"match": {"level": "ERROR"}}, {"match": {"app": "web"}}]}
        }

    def test_case_insensitive_or(self) -> None:
        assert kql_to_es("level:ERROR OR level:WARN") == {
            "bool": {
                "should": [{"match": {"level": "ERROR"}}, {"match": {"level": "WARN"}}],
                "minimum_should_match": 1,
            }
        }

    def test_case_insensitive_not(self) -> None:
        assert kql_to_es("NOT level:DEBUG") == {
            "bool": {"must_not": [{"match": {"level": "DEBUG"}}]}
        }


class TestImplicitAnd:
    def test_two_expressions(self) -> None:
        assert kql_to_es("level:ERROR app:web") == {
            "bool": {"filter": [{"match": {"level": "ERROR"}}, {"match": {"app": "web"}}]}
        }

    def test_three_expressions(self) -> None:
        result = kql_to_es("level:ERROR app:web status:500")
        assert result == {
            "bool": {
                "filter": [
                    {"match": {"level": "ERROR"}},
                    {"match": {"app": "web"}},
                    {"match": {"status": "500"}},
                ]
            }
        }


class TestChainFlattening:
    def test_and_chain(self) -> None:
        result = kql_to_es("a:1 and b:2 and c:3")
        assert result == {
            "bool": {
                "filter": [
                    {"match": {"a": "1"}},
                    {"match": {"b": "2"}},
                    {"match": {"c": "3"}},
                ]
            }
        }

    def test_or_chain(self) -> None:
        result = kql_to_es("a:1 or b:2 or c:3")
        assert result == {
            "bool": {
                "should": [
                    {"match": {"a": "1"}},
                    {"match": {"b": "2"}},
                    {"match": {"c": "3"}},
                ],
                "minimum_should_match": 1,
            }
        }


class TestPrecedence:
    def test_and_binds_tighter_than_or(self) -> None:
        result = kql_to_es("a:1 or b:2 and c:3")
        assert result == {
            "bool": {
                "should": [
                    {"match": {"a": "1"}},
                    {"bool": {"filter": [{"match": {"b": "2"}}, {"match": {"c": "3"}}]}},
                ],
                "minimum_should_match": 1,
            }
        }

    def test_not_binds_tightest(self) -> None:
        result = kql_to_es("a:1 and not b:2")
        assert result == {
            "bool": {
                "filter": [
                    {"match": {"a": "1"}},
                    {"bool": {"must_not": [{"match": {"b": "2"}}]}},
                ]
            }
        }


class TestGrouping:
    def test_parens_override_precedence(self) -> None:
        result = kql_to_es("(a:1 or b:2) and c:3")
        assert result == {
            "bool": {
                "filter": [
                    {
                        "bool": {
                            "should": [{"match": {"a": "1"}}, {"match": {"b": "2"}}],
                            "minimum_should_match": 1,
                        }
                    },
                    {"match": {"c": "3"}},
                ]
            }
        }

    def test_nested_parens(self) -> None:
        result = kql_to_es("((a:1))")
        assert result == {"match": {"a": "1"}}


class TestValueList:
    def test_or_list(self) -> None:
        result = kql_to_es("status:(200 or 404 or 500)")
        assert result == {
            "bool": {
                "should": [
                    {"match": {"status": "200"}},
                    {"match": {"status": "404"}},
                    {"match": {"status": "500"}},
                ],
                "minimum_should_match": 1,
            }
        }

    def test_and_list(self) -> None:
        result = kql_to_es("tags:(a and b)")
        assert result == {
            "bool": {"filter": [{"match": {"tags": "a"}}, {"match": {"tags": "b"}}]}
        }

    def test_not_in_list(self) -> None:
        result = kql_to_es("status:(200 or not 500)")
        assert result == {
            "bool": {
                "should": [
                    {"match": {"status": "200"}},
                    {"bool": {"must_not": [{"match": {"status": "500"}}]}},
                ],
                "minimum_should_match": 1,
            }
        }

    def test_wildcard_in_list(self) -> None:
        result = kql_to_es("app:(web* or api*)")
        assert result == {
            "bool": {
                "should": [
                    {"wildcard": {"app": {"value": "web*"}}},
                    {"wildcard": {"app": {"value": "api*"}}},
                ],
                "minimum_should_match": 1,
            }
        }

    def test_exists_in_list(self) -> None:
        result = kql_to_es("field:(*)")
        assert result == {"exists": {"field": "field"}}


class TestNestedQuery:
    def test_nested(self) -> None:
        result = kql_to_es("items:{ name:test and price > 10 }")
        assert result == {
            "nested": {
                "path": "items",
                "query": {
                    "bool": {
                        "filter": [
                            {"match": {"name": "test"}},
                            {"range": {"price": {"gt": 10}}},
                        ]
                    }
                },
            }
        }


class TestUnqualified:
    def test_bare_value(self) -> None:
        assert kql_to_es("ERROR") == {"query_string": {"query": "ERROR"}}

    def test_quoted_bare_value(self) -> None:
        assert kql_to_es('"error message"') == {"query_string": {"query": "error message"}}

    def test_match_all(self) -> None:
        assert kql_to_es("*") == {"match_all": {}}


class TestKeywordAsField:
    def test_not_as_field(self) -> None:
        assert kql_to_es("not:value") == {"match": {"not": "value"}}

    def test_and_as_field(self) -> None:
        assert kql_to_es("and:value") == {"match": {"and": "value"}}

    def test_or_as_field(self) -> None:
        assert kql_to_es("or:value") == {"match": {"or": "value"}}

    def test_not_field_with_range(self) -> None:
        assert kql_to_es("not > 5") == {"range": {"not": {"gt": 5}}}


class TestEscaping:
    def test_escaped_colon_in_field(self) -> None:
        assert kql_to_es("field\\:name:value") == {"match": {"field:name": "value"}}

    def test_escaped_keyword(self) -> None:
        result = kql_to_es("\\not:value")
        assert result == {"match": {"not": "value"}}

    def test_backslash_in_value(self) -> None:
        assert kql_to_es("path:C\\\\Windows") == {"match": {"path": "C\\Windows"}}


class TestSyntaxErrors:
    def test_empty_query(self) -> None:
        with pytest.raises(KQLSyntaxError, match="empty query"):
            kql_to_es("")

    def test_whitespace_only(self) -> None:
        with pytest.raises(KQLSyntaxError, match="empty query"):
            kql_to_es("   ")

    def test_unclosed_paren(self) -> None:
        with pytest.raises(KQLSyntaxError):
            kql_to_es("(level:ERROR")

    def test_unexpected_rparen(self) -> None:
        with pytest.raises(KQLSyntaxError):
            kql_to_es(")")

    def test_dangling_and(self) -> None:
        with pytest.raises(KQLSyntaxError):
            kql_to_es("level:ERROR and")

    def test_dangling_or(self) -> None:
        with pytest.raises(KQLSyntaxError):
            kql_to_es("level:ERROR or")

    def test_dangling_not(self) -> None:
        with pytest.raises(KQLSyntaxError):
            kql_to_es("not")

    def test_double_colon(self) -> None:
        with pytest.raises(KQLSyntaxError):
            kql_to_es("field::value")

    def test_unclosed_brace(self) -> None:
        with pytest.raises(KQLSyntaxError):
            kql_to_es("items:{ name:test")

    def test_trailing_tokens(self) -> None:
        with pytest.raises(KQLSyntaxError):
            kql_to_es("level:ERROR )")


class TestComplexQueries:
    def test_real_world_log_query(self) -> None:
        result = kql_to_es(
            'level:ERROR and kubernetes.labels.app:web-server and not message:"health check"'
        )
        assert result == {
            "bool": {
                "filter": [
                    {"match": {"level": "ERROR"}},
                    {"match": {"kubernetes.labels.app": "web-server"}},
                    {"bool": {"must_not": [{"match_phrase": {"message": "health check"}}]}},
                ]
            }
        }

    def test_mixed_operators(self) -> None:
        result = kql_to_es("(level:ERROR or level:WARN) and app:web and not status:200")
        assert result == {
            "bool": {
                "filter": [
                    {
                        "bool": {
                            "should": [
                                {"match": {"level": "ERROR"}},
                                {"match": {"level": "WARN"}},
                            ],
                            "minimum_should_match": 1,
                        }
                    },
                    {"match": {"app": "web"}},
                    {"bool": {"must_not": [{"match": {"status": "200"}}]}},
                ]
            }
        }

    def test_range_with_boolean(self) -> None:
        result = kql_to_es("bytes > 1000 and status:200")
        assert result == {
            "bool": {
                "filter": [
                    {"range": {"bytes": {"gt": 1000}}},
                    {"match": {"status": "200"}},
                ]
            }
        }
