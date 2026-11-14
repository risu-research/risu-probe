package mcp

// B38 original upstream PARSER-ONLY test. No stdio/native client claim.
// Compiles actual pinned upstream Go package, without editing any source.

import (
 "encoding/json"
 "fmt"
 "os"
 "strings"
 "testing"
)

func TestB38OriginalStructuredOnlyResultParser(t *testing.T) {
 side := os.Getenv("B38_UPSTREAM_ORIGINAL_SIDE")
 if side != "before" && side != "after" {
  t.Fatal("B38_UNVERIFIED_ORIGINAL_SIDE")
 }
 cases := []struct {
  name string
  raw string
  before bool
  after bool
  structured bool
  isError bool
 }{
  {"ordinary_text", `{"content":[{"type":"text","text":"normal"}]}`,true,true,false,false},
  {"structured_object_only", `{"structuredContent":{"answer":17}}`,false,true,true,false},
  {"structured_list_only", `{"structuredContent":[1,2]}`,false,true,true,false},
  {"both_text_and_structured", `{"content":[{"type":"text","text":"ok"}],"structuredContent":{"id":5}}`,true,true,true,false},
  {"error_with_text", `{"content":[{"type":"text","text":"INVALID"}],"isError":true}`,true,true,false,true},
  {"null_structured_only", `{"structuredContent":null}`,false,false,false,false},
  {"missing_both_channels", `{"isError":true}`,false,false,false,false},
  {"empty_object", `{}`,false,false,false,false},
 }
 for _,tc:=range cases{
  t.Run(tc.name,func(t *testing.T){
   raw:=json.RawMessage(tc.raw)
   result,err:=ParseCallToolResult(&raw)
   want:=tc.before
   if side=="after"{want=tc.after}
   if want{
    if err!=nil{t.Fatalf("B38_UNEXPECTED_REJECTION %s: %v",tc.name,err)}
    if result==nil{t.Fatal("B38_NO_PARSE_RESULT")}
    if tc.structured && result.StructuredContent==nil{t.Fatal("B38_STRUCTURED_LOST")}
    if tc.isError && !result.IsError{t.Fatal("B38_ISERROR_LOST")}
    fmt.Printf("B38_ORIGINAL_PARSER side=%s case=%s status=ACCEPT\n",side,tc.name)
   }else{
    if err==nil{t.Fatalf("B38_UNEXPECTED_ACCEPT %s: %+v",tc.name,result)}
    if !strings.Contains(err.Error(),"content is missing"){
     t.Fatalf("B38_WRONG_REJECT_REASON %s: %v",tc.name,err)
    }
    fmt.Printf("B38_ORIGINAL_PARSER side=%s case=%s status=REJECT\n",side,tc.name)
   }
  })
 }
 fmt.Printf("B38_ORIGINAL_PARSER_%s_8_CONTROLS_PASS\n",side)
}
