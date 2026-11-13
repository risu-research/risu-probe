"""B37 research-only algorithm and conservative normal controls (NO B37 upstream)."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from b37_semantic_preservation import analyze_source


def rules(code: str) -> set[str]:
    return {v["rule_id"] for v in analyze_source(code,"sample.py")["findings"]}


class B37SourceControls(unittest.TestCase):
    def test_constant_raise_discards_native_mcp_error_guidance(self):
        before="""
async def send(conn, name):
    result = await conn.call_tool(name, {})
    if result.isError:
        raise ValueError("MCP tool returned an error")
    return result.model_dump(mode="json")
"""
        after="""
async def send(conn, name):
    result = await conn.call_tool(name, {})
    if result.isError:
        raise ToolErrorResult(result.content)
    return result.model_dump(mode="json")
"""
        self.assertIn("RSEM104",rules(before))
        self.assertNotIn("RSEM104",rules(after))

    def test_structured_error_details_are_not_discarded_when_used(self):
        code="""
async def send(conn, name):
    result = await conn.call_tool(name, {})
    if result.is_error:
        raise ToolErrorResult(result.structured_content)
    return result
"""
        self.assertNotIn("RSEM104",rules(code))

    def test_status_less_return_of_content_is_a_source_hypothesis(self):
        bad="""
async def send(session):
    result = await session.call_tool("search",{})
    return result.content
"""
        good="""
async def send(session):
    result = await session.call_tool("search",{})
    if result.is_error:
        return {"error":result.content}
    return result.content
"""
        self.assertIn("RSEM105",rules(bad))
        self.assertNotIn("RSEM105",rules(good))

    def test_full_result_passthrough_is_normal(self):
        code="""
async def send(session):
    result = await session.call_tool("search",{})
    return result
"""
        self.assertEqual(rules(code),set())

    def test_unrelated_content_does_not_become_mcp_failure(self):
        code="""
def render(report):
    return report.content[0]
"""
        self.assertEqual(rules(code),set())

    def test_tool_decorator_json_object_into_str_requires_review(self):
        bad="""
@mcp.tool()
def report() -> str:
    return json.dumps({"count":3,"items":[1,2]})
"""
        self.assertIn("RSEM106",rules(bad))

    def test_text_return_annotated_plain_string_is_normal(self):
        good="""
@mcp.tool()
def ping() -> str:
    return "pong"
"""
        self.assertNotIn("RSEM106",rules(good))

    def test_json_string_literal_is_normal_string_result(self):
        good="""
@mcp.tool()
def ping() -> str:
    return json.dumps("pong")
"""
        self.assertNotIn("RSEM106",rules(good))

    def test_regular_python_helper_json_encoder_outside_mcp_is_normal(self):
        good="""
def serialize(data) -> str:
    return json.dumps(data)
"""
        self.assertNotIn("RSEM106",rules(good))

    def test_normal_mcp_lists_return_mapping(self):
        good="""
@mcp.tool()
async def users() -> dict[str, object]:
    return {"items":[{"id":1}]}
"""
        self.assertNotIn("RSEM106",rules(good))

    def test_partial_recovery_of_valid_function_with_unrelated_invalid_except(self):
        bad="""
async def project(session):
    response = await session.call_tool("x")
    return response.content[0]

def unrelated():
    try:
        x = 1
    except ValueError, TypeError:
        x = 2
    return x

async def preserve(session):
    response = await session.call_tool("y")
    return response
"""
        record=analyze_source(bad,"source.py")
        self.assertEqual(record["coverage"],"PARTIAL_AST")
        self.assertTrue(record["negative_claims_prohibited"])
        self.assertGreaterEqual(record["recovered_functions"],2)
        self.assertGreaterEqual(record["incomplete_regions"],1)
        self.assertTrue(any(x["rule_id"]=="RSEM102" and x["function"]=="project"
                            for x in record["findings"]))
        self.assertFalse(any(x["function"]=="preserve" for x in record["findings"]))
        self.assertEqual(record["parse_error"]["line"],8)

    def test_valid_module_must_not_downgrade_to_partial(self):
        record=analyze_source("def f():\n    return 42\n","normal.py")
        self.assertEqual(record["coverage"],"COMPLETE_AST")
        self.assertIsNone(record["parse_error"])
        self.assertEqual(record["findings"],[])

    def test_entirely_invalid_module_reports_coverage_limit(self):
        record=analyze_source("except ValueError, TypeError:\n    pass\n","bad.py")
        self.assertEqual(record["coverage"],"UNVERIFIED_NO_RECOVERABLE_FUNCTIONS")
        self.assertEqual(record["findings"],[])

    def test_preserves_line_of_recovered_function(self):
        text="# license\n\n\nasync def project(session):\n    response = await session.call_tool('x')\n    return response.content[0]\n\nx = [\n"
        record=analyze_source(text,"original.py")
        self.assertEqual(record["coverage"],"PARTIAL_AST")
        line=next(x["line"] for x in record["findings"] if x["rule_id"]=="RSEM102")
        self.assertEqual(line,6)

    def test_no_source_execution_or_runtime_confirmation(self):
        out=analyze_source("""
async def project(session):
    response = await session.call_tool('x')
    return response.content[0]
""","original.py")
        self.assertTrue(out["source_hypotheses_only"])
        self.assertFalse(out["third_party_code_executed"])
        self.assertTrue(all(x["classification"]=="SOURCE_HYPOTHESIS"
                            for x in out["findings"]))


if __name__=="__main__":
    unittest.main()
