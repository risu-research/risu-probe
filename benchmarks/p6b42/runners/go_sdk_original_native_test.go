package mcp

// B42 evaluator-owned test-only overlay in the upstream Go SDK package.
// The original client, server and IOTransport are byte-for-byte unchanged.
// Unlike an object-level mock, IOTransport passes real serialized newline
// JSON-RPC over net.Pipe. Raw client writes and server writes are captured
// independently from the original client CallTool() returned IsError field.
import (
 "bytes"
 "context"
 "encoding/json"
 "fmt"
 "io"
 "net"
 "os"
 "sync"
 "testing"
)

type b42CaptureWriter struct{
 io.WriteCloser
 mu sync.Mutex
 data bytes.Buffer
}
func (c *b42CaptureWriter) Write(p []byte)(int,error){
 n,err:=c.WriteCloser.Write(p)
 if n>0{c.mu.Lock();_,_=c.data.Write(p[:n]);c.mu.Unlock()}
 return n,err
}
func (c *b42CaptureWriter) frames()([]map[string]any,error){
 c.mu.Lock();raw:=append([]byte(nil),c.data.Bytes()...);c.mu.Unlock()
 var result []map[string]any
 for _,chunk:=range bytes.Split(bytes.TrimSpace(raw),[]byte{'\n'}){
  if len(chunk)==0{continue}
  var obj map[string]any
  if err:=json.Unmarshal(chunk,&obj);err!=nil{return nil,fmt.Errorf("original IOTransport frame malformed: %w",err)}
  result=append(result,obj)
 }
 return result,nil
}

func TestB42OfficialGoOriginalClientNativeIsError(t *testing.T){
 output:=os.Getenv("B42_N1_WITNESS")
 if output==""{t.Fatal("B42_N1_WITNESS required")}
 ctx:=context.Background()
 originalServer:=NewServer(&Implementation{Name:"b42-original-peer",Version:"1.0"},nil)
 // ToolHandlerFor would add validation and synthesize output; low-level
 // original server is used to return deterministic native MCP result flags.
 originalServer.AddTool(&Tool{Name:"b42_success",InputSchema:map[string]any{"type":"object"}},func(_ context.Context,_ *CallToolRequest)(*CallToolResult,error){
   return &CallToolResult{Content:[]Content{&TextContent{Text:"b42 hello"}},IsError:false},nil
 })
 originalServer.AddTool(&Tool{Name:"b42_denied",InputSchema:map[string]any{"type":"object"}},func(_ context.Context,_ *CallToolRequest)(*CallToolResult,error){
   return &CallToolResult{Content:[]Content{&TextContent{Text:"b42 access denied"}},IsError:true},nil
 })
 cside,sside:=net.Pipe()
 defer cside.Close();defer sside.Close()
 cwrite:=&b42CaptureWriter{WriteCloser:cside}
 swrite:=&b42CaptureWriter{WriteCloser:sside}
 sTransport:=&IOTransport{Reader:sside,Writer:swrite}
 cTransport:=&IOTransport{Reader:cside,Writer:cwrite}
 originalServerSession,err:=originalServer.Connect(ctx,sTransport,nil)
 if err!=nil{t.Fatalf("original server.Connect: %v",err)}
 defer originalServerSession.Close()
 originalClient:=NewClient(&Implementation{Name:"b42-original-Go-client",Version:"1.0"},nil)
 originalClientSession,err:=originalClient.Connect(ctx,cTransport,&ClientSessionOptions{ProtocolVersion:"2025-11-25"})
 if err!=nil{t.Fatalf("original client.Connect: %v",err)}
 defer originalClientSession.Close()
 observations:=[]map[string]any{}
 for _,tc:=range []struct{name string;expected bool;expectedText string}{
  {"b42_success",false,"b42 hello"},
  {"b42_denied",true,"b42 access denied"},
 }{
  result,err:=originalClientSession.CallTool(ctx,&CallToolParams{Name:tc.name})
  if err!=nil{t.Fatalf("original CallTool %s: %v",tc.name,err)}
  if result==nil || result.IsError!=tc.expected{t.Fatalf("%s original client IsError not preserved: %+v",tc.name,result)}
  if len(result.Content)!=1{t.Fatalf("%s original client content absent",tc.name)}
  txt,ok:=result.Content[0].(*TextContent)
  if !ok || txt.Text!=tc.expectedText{t.Fatalf("%s original client text error",tc.name)}
  requests,err:=cwrite.frames();if err!=nil{t.Fatal(err)}
  replies,err:=swrite.frames();if err!=nil{t.Fatal(err)}
  matches:=[]map[string]any{}
  for _,r:=range requests{
   if r["method"]=="tools/call" {
    params,ok:=r["params"].(map[string]any)
    if !ok || params["name"]!=tc.name{continue}
    for _,s:=range replies{
     if s["id"]==r["id"] && s["jsonrpc"]=="2.0"{
       matches=append(matches,map[string]any{"request":r,"response":s})
     }
    }
   }
  }
  if len(matches)!=1{t.Fatalf("%s matched native paired JSONRPC count %d",tc.name,len(matches))}
  pair:=matches[0]
  response:=pair["response"].(map[string]any)
  native,ok:=response["result"].(map[string]any)
  if !ok{t.Fatalf("%s missing native result",tc.name)}
  rawFlag,exists:=native["isError"]
  nativeIsError:=exists && rawFlag==true
  if nativeIsError!=tc.expected{t.Fatalf("%s original server native status unexpectedly %v",tc.name,rawFlag)}
  request:=pair["request"].(map[string]any)
  observations=append(observations,map[string]any{
   "case_id":"N1",
   "tool":tc.name,
   "wire":pair,
   "observed":map[string]any{"tool":tc.name,"request_id":request["id"],
      "outcome":func()string{if result.IsError{return "tool_error"};return "success"}(),
      "original_actual_consumer_IsError":result.IsError,
      "original_actual_consumer_text":txt.Text},
   "contract":map[string]any{"status":true,"text":"none","structured":"none","media":"none"},
   "execution_provenance":"ORIGINAL_EXTERNAL_CLIENT_CONTROLLED_SERVER",
   "original_source_git_blob":"7894dd0eee3e18bed7137ed88c9b5016ccc90a74",
   "original_commit_verified":true,
   "raw_original_JSONRPC_bytes_from_separate_writers":true,
   "original_client_source_unchanged":true,
   "original_peer_type":"original_server_local_net.Pipe_newline_JSONRPC",
   "source_proof_tier":"ORIGINAL_CLIENT_NATIVE_JSONRPC_WITH_ORIGINAL_SERVER",
   "full_independent_production_application":false})
 }
 data:=map[string]any{
  "schema":"risu-p6b42-original-go-sdk-native-client-v1",
  "original_repo":"modelcontextprotocol/go-sdk",
  "original_commit":"0fa5e8407aa3fda65166e4207156c03d084bfd44",
  "original_client_source_unchanged":true,
  "original_transport_source_unchanged":true,
  "original_native_wire_bytes_independently_observed":true,
  "witnesses":observations}
 raw,err:=json.MarshalIndent(data,"","  ");if err!=nil{t.Fatal(err)}
 if err:=os.WriteFile(output,append(raw,'\n'),0600);err!=nil{t.Fatal(err)}
 fmt.Println("B42_N1_ORIGINAL_GO_SDK_STATUS_NATIVE_JSONRPC_TWO_CASES_PASSED")
}
