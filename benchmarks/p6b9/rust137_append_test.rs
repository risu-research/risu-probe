
#[cfg(test)]
mod risu_b9_heldout_137 {
    use super::*;
    use std::fs;
    #[test]
    fn actual_upstream_toolcall_structured_roundtrip_capture() {
        // Operates on the real upstream ToolCallResult type in each pinned Git tree.
        // No external MCP endpoint or CLI interaction; this tests the serializer boundary.
        let issue = serde_json::json!({
            "content":[{"type":"text","text":"Synthetic human summary"}],
            "isError":false,
            "structuredContent":{"count":7,"items":["x","y"]},
            "resultType":"complete"
        });
        let normal = serde_json::json!({
            "content":[{"type":"text","text":"Only unstructured result"}],
            "isError":false
        });
        let typed_issue: ToolCallResult=serde_json::from_value(issue.clone()).unwrap();
        let typed_control: ToolCallResult=serde_json::from_value(normal.clone()).unwrap();
        let round_issue=serde_json::to_value(typed_issue).unwrap();
        let round_control=serde_json::to_value(typed_control).unwrap();
        let report=serde_json::json!({
            "schema":"risu-p6b9-rust137-original-type-roundtrip-v1",
            "source":"ACTUAL_UPSTREAM_RUST_TOOLCALLRESULT_SERDE_COMPONENT_NOT_FULL_CLI",
            "issue_original":issue,
            "issue_roundtrip":round_issue,
            "control_original":normal,
            "control_roundtrip":round_control
        });
        let path=std::env::var("RISU_B9_RUST_CAPTURE_PATH").unwrap();
        fs::write(path,serde_json::to_vec_pretty(&report).unwrap()).unwrap();
        println!("RISU_B9_RUST137_SOURCE_CAPTURED");
    }
}
