package model

// B42 evaluation-only type audit of unchanged original Leather tool trace.
// It does not infer a missing completion from a single aggregate trace record.
import (
 "encoding/json"
 "os"
 "reflect"
 "testing"
 "fmt"
)
func TestB42OriginalLeatherCompletionTraceEligibility(t *testing.T){
 out:=os.Getenv("B42_C2_ELIGIBILITY_FILE")
 if out==""{t.Fatal("missing B42_C2_ELIGIBILITY_FILE")}
 typ:=reflect.TypeOf(ToolTrace{})
 fields:=[]map[string]any{}
 var hasStableCallID,hasOriginalStartedEvent,hasTerminalEvent bool
 for i:=0;i<typ.NumField();i++{
  field:=typ.Field(i)
  fields=append(fields,map[string]any{"field":field.Name,"json":field.Tag.Get("json")})
  if field.Name=="ID"||field.Name=="ToolUseID"||field.Name=="CallID"{hasStableCallID=true}
  if field.Name=="StartedEvent"{hasOriginalStartedEvent=true}
  if field.Name=="TerminalEvent"{hasTerminalEvent=true}
 }
 result:=map[string]any{
  "schema":"risu-p6b42-original-leather-type-audit-v1",
  "repo":"TGPSKI/leather",
  "original_commit":"c2d4da6d5022b42be5ff9818dd0f6d8900314769",
  "source_git_blob":"c194da6a186a4e360eeb8527fbed50514429a60e",
  "actual_original_go_type":"model.ToolTrace",
  "original_reflected_fields":fields,
  "stable_call_id_exposed":hasStableCallID,
  "distinct_started_event_exposed":hasOriginalStartedEvent,
  "distinct_terminal_event_exposed":hasTerminalEvent,
  "meets_C42_COMPLETE_1":hasStableCallID&&hasOriginalStartedEvent&&hasTerminalEvent,
  "original_source_unchanged":true,
  "not_counted_as_completion_omission_negative_or_positive":true,
 }
 if result["meets_C42_COMPLETE_1"]==true{t.Fatal("original trace now eligible; revisit under sealed contract before scoring")}
 raw,err:=json.MarshalIndent(result,"","  ");if err!=nil{t.Fatal(err)}
 if err=os.WriteFile(out,append(raw,'\n'),0600);err!=nil{t.Fatal(err)}
 fmt.Println("B42_C2_ORIGINAL_TRACE_NO_MATCHED_START_TERMINAL_EVENT_API_NOT_SCORED")
}
