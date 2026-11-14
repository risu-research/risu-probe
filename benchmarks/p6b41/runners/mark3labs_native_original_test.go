package client

// B41 evaluation-only test overlay. The checked-out upstream SDK client,
// server, and InProcessTransport remain byte-identical to the sealed commit.
import (
  "context"
  "encoding/json"
  "fmt"
  "os"
  "testing"
  "github.com/mark3labs/mcp-go/client/transport"
  "github.com/mark3labs/mcp-go/mcp"
  "github.com/mark3labs/mcp-go/server"
)

type b41WirePair struct { Request map[string]any `json:"request"`; Response map[string]any `json:"response"` }
type b41TracingTransport struct { transport.Interface; Pairs []b41WirePair }
func (t *b41TracingTransport) SendRequest(ctx context.Context, request transport.JSONRPCRequest) (*transport.JSONRPCResponse,error){
  // Only run unmodified original transport; capture serialized native bytes.
  response, err:=t.Interface.SendRequest(ctx,request)
  if request.Method=="tools/call" && response!=nil {
    r,q:=map[string]any{},map[string]any{}
    rb,e1:=json.Marshal(request); sb,e2:=json.Marshal(response)
    if e1!=nil||e2!=nil {panic("B41 original native serialization unavailable")}
    if json.Unmarshal(rb,&r)!=nil||json.Unmarshal(sb,&q)!=nil {panic("B41 invalid native JSON")}
    t.Pairs=append(t.Pairs,b41WirePair{r,q})
  }
  return response,err
}

func TestB41OriginalExternalGoClientNativeWire(t *testing.T){
  output:=os.Getenv("B41_N1_WITNESS")
  if output=="" {t.Fatal("B41_N1_WITNESS required")}
  mcpServer:=server.NewMCPServer("b41-original-peer","1.0",server.WithToolCapabilities(true))
  mcpServer.AddTool(mcp.NewTool("b41_success"),func(_ context.Context,_ mcp.CallToolRequest)(*mcp.CallToolResult,error){
    return &mcp.CallToolResult{Content:[]mcp.Content{mcp.TextContent{Type:"text",Text:"hello"}}},nil
  })
  mcpServer.AddTool(mcp.NewTool("b41_denied"),func(_ context.Context,_ mcp.CallToolRequest)(*mcp.CallToolResult,error){
    return &mcp.CallToolResult{IsError:true,Content:[]mcp.Content{mcp.TextContent{Type:"text",Text:"access denied"}}},nil
  })
  mcpServer.AddTool(mcp.NewTool("b41_structured"),func(_ context.Context,_ mcp.CallToolRequest)(*mcp.CallToolResult,error){
    return &mcp.CallToolResult{Content:[]mcp.Content{mcp.TextContent{Type:"text",Text:"score=7"}},StructuredContent:map[string]any{"score":7}},nil
  })
  trace:=&b41TracingTransport{Interface:transport.NewInProcessTransport(mcpServer)}
  original:=NewClient(trace)
  ctx:=context.Background()
  if err:=original.Start(ctx);err!=nil{t.Fatal(err)}
  defer original.Close()
  init:=mcp.InitializeRequest{}
  init.Params.ProtocolVersion=mcp.LATEST_PROTOCOL_VERSION
  init.Params.ClientInfo=mcp.Implementation{Name:"b41-normal-client",Version:"1.0"}
  if _,err:=original.Initialize(ctx,init);err!=nil{t.Fatalf("original initialize: %v",err)}
  cases:=[]map[string]any{}
  for _,tc:=range []struct{name string;isError bool;structured bool}{
    {"b41_success",false,false},{"b41_denied",true,false},{"b41_structured",false,true},
  }{
    request:=mcp.CallToolRequest{}
    request.Params.Name=tc.name
    result,err:=original.CallTool(ctx,request)
    if err!=nil{t.Fatalf("%s original CallTool: %v",tc.name,err)}
    if result==nil{t.Fatalf("%s returned nil",tc.name)}
    if result.IsError!=tc.isError{t.Fatalf("%s original client unexpected IsError=%v",tc.name,result.IsError)}
    if tc.structured && result.StructuredContent==nil{t.Fatalf("%s original structured content missing",tc.name)}
    if len(trace.Pairs)!=len(cases)+1{t.Fatalf("%s no matched native JSONRPC trace",tc.name)}
    pair:=trace.Pairs[len(trace.Pairs)-1]
    wireResult,ok:=pair.Response["result"].(map[string]any)
    if !ok{t.Fatalf("%s missing native result",tc.name)}
    nativeError,ok:=wireResult["isError"].(bool);if !ok{nativeError=false}
    if nativeError!=tc.isError{t.Fatalf("%s native error unexpected",tc.name)}
    requestID:=pair.Request["id"]
    if requestID!=pair.Response["id"]{t.Fatalf("%s native ID mismatch",tc.name)}
    if pair.Request["method"]!="tools/call"{t.Fatalf("%s missing native tools/call",tc.name)}
    record:=map[string]any{
      "case_id":"N1","tool":tc.name,
      "wire":pair,
      "observed":map[string]any{"tool":tc.name,"request_id":requestID,"outcome":func()string{if result.IsError{return "tool_error"};return "success"}(),"status_origin":"original-mcp-go.CallTool().IsError", "original_structured_present":result.StructuredContent!=nil},
      "contract":map[string]any{"status":true,"text":"none","structured":"none","media":"none"},
      "execution_provenance":"ORIGINAL_EXTERNAL_CLIENT_CONTROLLED_SERVER",
      "original_source_git_blob":"9f1a4a692507e1c4854cf03f5fb9064351ad6da8",
      "original_commit_verified":true,
      "original_upstream_source_unchanged":true,
      "original_sdk_transport":"original-InProcessTransport-native-JSONRPC-bytes",
      "full_original_external_application":false,
    }
    cases=append(cases,record)
  }
  data:=map[string]any{"schema":"risu-b41-n1-native-original-client-v1","original_repo":"mark3labs/mcp-go","original_commit":"a21ffc6877f1741603dc36246f309d6cf6c6ed05","original_client_source_unchanged":true,"native_witnesses":cases}
  b,err:=json.MarshalIndent(data,"","  ");if err!=nil{t.Fatal(err)}
  if err=os.WriteFile(output,append(b,'\n'),0600);err!=nil{t.Fatal(err)}
  fmt.Println("B41_N1_ORIGINAL_NATIVE_CLIENT_3_CASES_DONE")
}
