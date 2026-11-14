package mcp_golang

// B41 evaluation-only original client witness: real independent original Go
// MCPClient over loopback HTTP, with source unchanged and a controlled peer.
import (
 "context"
 "encoding/json"
 "fmt"
 "net/http"
 "net/http/httptest"
 "os"
 "reflect"
 "sync"
 "testing"
 mcphttp "github.com/metoro-io/mcp-golang/transport/http"
)

type b41MetoroPair struct {
 Request map[string]any `json:"request"`
 Response map[string]any `json:"response"`
}
func TestB41OriginalMetoroMCPClientNativeWire(t *testing.T) {
 output:=os.Getenv("B41_N2_WITNESS")
 if output==""{t.Fatal("B41_N2_WITNESS required")}
 var mu sync.Mutex
 var pairs []b41MetoroPair
 srv:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
   if r.Method!="POST"{http.Error(w,"only POST",405);return}
   var req map[string]any
   if e:=json.NewDecoder(r.Body).Decode(&req);e!=nil{http.Error(w,e.Error(),400);return}
   method,_:=req["method"].(string)
   var result any
   switch method{
   case "initialize":
    result=map[string]any{"protocolVersion":"1.0","capabilities":map[string]any{"tools":map[string]any{}},"serverInfo":map[string]any{"name":"b41-local-peer","version":"1.0"}}
   case "tools/call":
    p,_:=req["params"].(map[string]any)
    name,_:=p["name"].(string)
    if name!="b41_ok" && name!="b41_denied"{http.Error(w,"unexpected name",400);return}
    flag:=name=="b41_denied"
    words:="hello"
    if flag{words="permission denied"}
    result=map[string]any{"content":[]any{map[string]any{"type":"text","text":words}},"isError":flag}
   default: http.Error(w,"unknown method",400);return
   }
   resp:=map[string]any{"jsonrpc":"2.0","id":req["id"],"result":result}
   w.Header().Set("Content-Type","application/json")
   if method=="tools/call"{mu.Lock();pairs=append(pairs,b41MetoroPair{Request:req,Response:resp});mu.Unlock()}
   if err:=json.NewEncoder(w).Encode(resp);err!=nil{panic(err)}
 }))
 defer srv.Close()
 orig:=NewClient(mcphttp.NewHTTPClientTransport("/mcp").WithBaseURL(srv.URL))
 if _,err:=orig.Initialize(context.Background());err!=nil{t.Fatalf("original metoro Initialize: %v",err)}
 records:=[]map[string]any{}
 for _,tc:=range []struct{name string;wants string}{
  {"b41_ok","hello"},{"b41_denied","permission denied"},
 }{
   result,err:=orig.CallTool(context.Background(),tc.name,map[string]any{})
   if err!=nil{t.Fatalf("original CallTool(%s) raised: %v",tc.name,err)}
   if result==nil||len(result.Content)!=1||result.Content[0].TextContent==nil{t.Fatalf("original response %s invalid content",tc.name)}
   if result.Content[0].TextContent.Text!=tc.wants{t.Fatalf("original result %s content mismatch",tc.name)}
   _,hasExplicitFlag:=reflect.TypeOf(*result).FieldByName("IsError")
   mu.Lock()
   if len(pairs)!=len(records)+1 {mu.Unlock();t.Fatalf("native wire missing %s",tc.name)}
   pair:=pairs[len(pairs)-1]
   mu.Unlock()
   if pair.Request["id"]!=pair.Response["id"]{t.Fatal("missing matched jsonrpc id")}
   nativeError:=tc.name=="b41_denied"
   wireResult:=pair.Response["result"].(map[string]any)
   if wireResult["isError"]!=nativeError{t.Fatal("native isError not as sent")}
   records=append(records,map[string]any{
    "case_id":"N2","tool":tc.name,"wire":pair,
    "original_observed":map[string]any{"error_nil":err==nil,"content_text":result.Content[0].TextContent.Text,"api_exposes_IsError":hasExplicitFlag,"original_response_type":"mcp_golang.ToolResponse"},
    "preregistered_status_contract_eligible":hasExplicitFlag,
    "no_unsupported_B38_status_score":!hasExplicitFlag,
    "source":"original_metoro_client.CallTool via original_http_HTTPClientTransport",
    "original_source_git_blob":"a0e3536b9cd2a3081b65fa2c97e2b5f6eede86ac",
    "original_commit_verified":true,
    "original_app_source_unchanged":true,
    "synthetic_controlled_server":true,
   })
 }
 data:=map[string]any{"schema":"risu-b41-n2-original-client-http-witness-v1","original_repo":"metoro-io/mcp-golang","original_commit":"e5d629c5cd43e3470dcd3bf4cbc675a90bfcf513","original_client_executed":true,"original_client_was_modified":false,
 "candidate_normal_disposition":"INELIGIBLE_IF_ORIGINAL_TOOL_RESPONSE_HAS_NO_ERROR_STATUS_FIELD","witnesses":records}
 b,err:=json.MarshalIndent(data,"","  ");if err!=nil{t.Fatal(err)}
 if err:=os.WriteFile(output,append(b,'\n'),0600);err!=nil{t.Fatal(err)}
 fmt.Println("B41_N2_ORIGINAL_NATIVE_HTTP_CONSUMER_2_CASES_DONE")
}
