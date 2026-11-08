package server

// P6-B9 independent heldout: append-only test fixture executed against
// two unmodified public upstream versions of mcp-go.
import (
 "context"
 "encoding/json"
 "fmt"
 "os"
 "testing"
 "github.com/mark3labs/mcp-go/mcp"
)

func TestRisuB9RawStructuredOutput(t *testing.T) {
 srv := NewMCPServer("risu-b9-synthetic", "1.0.0", WithOutputSchemaValidation())
 schema := json.RawMessage(`{"type":"object","properties":{"temperature":{"type":"number"}},"required":["temperature"]}`)
 input := json.RawMessage(`{"type":"object","properties":{"id":{"type":"integer"}},"required":["id"]}`)
 for _,tc := range []struct{name string; value json.RawMessage}{
  {"bad_raw",json.RawMessage(`{"temperature":"not-a-number"}`)},
  {"good_raw",json.RawMessage(`{"temperature":21}`)},
 }{
  tc:=tc
  srv.AddTool(mcp.Tool{
    Name:tc.name,RawInputSchema:input,RawOutputSchema:schema,
  }, func(ctx context.Context,req mcp.CallToolRequest)(*mcp.CallToolResult,error){
    return &mcp.CallToolResult{
       Content:[]mcp.Content{mcp.NewTextContent("synthetic")},
       RawStructuredContent:tc.value,
    },nil
  })
 }
 observed:=map[string]interface{}{}
 for _,name:=range []string{"bad_raw","good_raw"}{
   payload,_:=json.Marshal(map[string]interface{}{
     "jsonrpc":"2.0","id":1,"method":"tools/call",
     "params":map[string]interface{}{"name":name,"arguments":map[string]interface{}{"id":2}},
   })
   response:=srv.HandleMessage(context.Background(),payload)
   serialized,err:=json.Marshal(response)
   if err!=nil {t.Fatal(err)}
   var env map[string]interface{}
   if err=json.Unmarshal(serialized,&env);err!=nil {t.Fatal(err)}
   // The genuine SDK response is preserved; the adapter never invents its result.
   observed[name]=env
 }
 output:=map[string]interface{}{
   "schema":"risu-p6b9-go1139-real-mcpserver-jsonrpc-v1",
   "source":"REAL_UPSTREAM_GO_MCP_SERVER_HANDLEMESSAGE",
   "cases":observed,
 }
 b,err:=json.MarshalIndent(output,"","  ")
 if err!=nil {t.Fatal(err)}
 out:=os.Getenv("RISU_B9_GO_CAPTURE_PATH")
 if out=="" {t.Fatal("RISU_B9_GO_CAPTURE_PATH unset")}
 if err=os.WriteFile(out,append(b,'\n'),0600);err!=nil {t.Fatal(err)}
 fmt.Println("RISU_B9_GO_UPSTREAM_CAPTURED")
}
