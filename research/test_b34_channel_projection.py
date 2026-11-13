"""P6-B34 development-only channel-projection algorithm tests (not B35 tests)."""
from __future__ import annotations
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "research"))
from b34_channel_projection import analyze_source


def ids(src: str) -> set[str]:
    return {x["rule_id"] for x in analyze_source(src, "normal.py")["findings"]}


class ChannelProjectionAlgorithmTests(unittest.TestCase):
    def test_structured_only_content_is_not_silently_projected(self):
        before = """
async def invoke(session, name):
    response = await session.call_tool(name)
    return ToolChunk(content=convert(response.content), state=response.is_error)
"""
        after = """
async def invoke(session, name):
    response = await session.call_tool(name)
    payload = convert(response.content)
    if response.structured_content is not None:
        payload.extend(encode(response.structured_content))
    return ToolChunk(content=payload, state=response.is_error)
"""
        self.assertIn("RSEM101", ids(before))
        self.assertNotIn("RSEM101", ids(after))

    def test_text_only_block_projection_has_missing_media_branch(self):
        before = """
async def invoke(session, name):
    response = await session.call_tool(name)
    pieces = []
    for item in (response.content or []):
        if hasattr(item, "text"):
            pieces.append(item.text)
    return json.dumps(pieces)
"""
        after = """
async def invoke(session, name):
    response = await session.call_tool(name)
    pieces = []
    for item in (response.content or []):
        if hasattr(item, "text") and item.text:
            pieces.append(item.text)
            continue
        media = cache_image(item)
        if media:
            pieces.append(media)
    return json.dumps(pieces)
"""
        self.assertIn("RSEM103", ids(before))
        self.assertNotIn("RSEM103", ids(after))

    def test_error_summary_is_not_misreported_as_success_media_dropping(self):
        src = """
async def invoke(session):
    output = await session.call_tool("x")
    if output.isError:
        for item in output.content:
            if hasattr(item, "text"):
                logger.error(item.text)
        return {"error": "failed"}
    return output
"""
        self.assertNotIn("RSEM103", ids(src))

    def test_first_content_only_is_a_candidate(self):
        before = """
async def invoke(session):
    answer = await session.call_tool("x")
    return answer.content[0]
"""
        after = """
async def invoke(session):
    answer = await session.call_tool("x")
    return join_contents(answer.content)
"""
        self.assertIn("RSEM102", ids(before))
        self.assertNotIn("RSEM102", ids(after))

    def test_returning_original_object_does_not_drop_channel(self):
        self.assertEqual(ids("""
async def invoke(session):
    obj = await session.call_tool("x")
    return obj
"""), set())

    def test_explicit_typed_result_parameter_requires_no_project_specific_name(self):
        src = """
def convert(answer: CallToolResult):
    return {"content": answer.content}
"""
        self.assertIn("RSEM101", ids(src))

    def test_bounded_static_only_and_no_ground_truth_claims(self):
        src = """
async def check(session):
    x = await session.call_tool("x")
    return ToolChunk(content=consume(x.content))
"""
        record=analyze_source(src, "item.py")
        self.assertTrue(record["source_hypotheses_only"])
        self.assertFalse(record["third_party_code_executed"])
        self.assertEqual(record["scope"], "PYTHON_AST_READONLY_SINGLE_SOURCE")
        self.assertEqual(record["findings"][0]["classification"], "SOURCE_HYPOTHESIS")

    def test_no_false_positive_for_unrelated_content_container(self):
        src = """
def parse_report(report):
    return report.content[0]
"""
        self.assertEqual(ids(src), set())


if __name__ == "__main__":
    unittest.main()
