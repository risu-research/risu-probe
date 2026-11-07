"""P6-B source-only conservative code-path tests; never execute scanned source."""
import tempfile,unittest
from pathlib import Path
from risu_static import scan
OLD="""class Tool:
    def convert_result(self, raw_value):
        if self.output_schema is None: pass
        try:
            value = _serialize_to_jsonable(raw_value)
        except (pydantic_core.PydanticSerializationError, UnicodeDecodeError):
            return ToolResult(content=content)
        return ToolResult(content=content, structured_content=value)
"""
FIX=OLD.replace("except (pydantic_core.PydanticSerializationError, UnicodeDecodeError):",
                "except (pydantic_core.PydanticSerializationError, UnicodeDecodeError) as e:\n            if self.output_schema is not None:\n                raise ToolError(str(e)) from e")
NO_SCHEMA=OLD.replace("if self.output_schema is None: pass","pass")
class PublicRule(unittest.TestCase):
    def ids(self,source):
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/'probe.py'
            path.write_text(source)
            report=scan(path)
            self.assertEqual(report['summary']['python_parsed'],1,'Fixture must be parseable Python')
            return [x for x in report['findings'] if x['rule_id']=='RPY204']
    def test_unprotected_fallback_suspected(self):
        results=self.ids(OLD)
        self.assertEqual(len(results),1)
        self.assertEqual(results[0]['verdict'],'SUSPECTED_LOSS')
    def test_repaired_fallback_not_flagged(self):
        self.assertEqual(self.ids(FIX),[])
    def test_without_output_schema_read_not_flagged(self):
        self.assertEqual(self.ids(NO_SCHEMA),[])
    def test_wrong_schema_guard_does_not_count_as_fix(self):
        wrong=OLD.replace("except (pydantic_core.PydanticSerializationError, UnicodeDecodeError):",
                          "except (pydantic_core.PydanticSerializationError, UnicodeDecodeError) as e:\n            if self.output_schema is None:\n                raise ToolError(str(e)) from e")
        self.assertEqual(len(self.ids(wrong)),1)
    def test_no_serialize_call_means_no_signal(self):
        unrelated="class Adapter:\n    def method(self):\n        self.output_schema = None\n        return ToolResult(content='safe')\n"
        self.assertEqual(self.ids(unrelated),[])
    def test_no_project_code_executed(self):
        with tempfile.TemporaryDirectory() as root:
            marker=Path(root)/'DO_NOT_CREATE'
            (Path(root)/'probe.py').write_text(f"from pathlib import Path\nPath({str(marker)!r}).touch()\n")
            scan(Path(root))
            self.assertFalse(marker.exists())
if __name__=='__main__':unittest.main()
