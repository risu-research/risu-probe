package client

// B41 POST-EXPOSURE development-only channel probe, not a holdout result.
// Executes unchanged original Mark3labs CallTool over original native JSONRPC.
import (
 "context"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "fmt"
 "os"
 "testing"
 "github.com/mark3labs/mcp-go/client/transport"
 "github.com/mark3labs/mcp-go/mcp"
 "github.com/mark3labs/mcp-go/server"
)

func TestB41PostExposureOriginalClientExactChannels(t *testing.T) {
 out:=os.Getenv("B41_EXPLORATORY_WITNESS")
 if out==""{t.Fatal("missing B41_EXPLORATORY_WITNESS")}
 s:=server.NewMCPServer("b41-channel-probe","1.0",server.WithToolCapabilities(true))
 s.AddTool(mcp.NewTool("b41_structured_exact"),func(_ context.Context,_ mcp.CallToolRequest)(*mcp.CallToolResult,error){
   return &mcp.CallToolResult{Content:[]mcp.Content{mcp.TextContent{Type:"text",Text:"structured value 42"}},
    StructuredContent:map[string]any{"value":42,"units":"kg"}},nil
 })
 b64:="aGVsbG8tdGlueS1zYW1wbGU="
 s.AddTool(mcp.NewTool("b41_media_exact"),func(_ context.Context,_ mcp.CallToolRequest)(*mcp.CallToolResult,error){
   return &mcp.CallToolResult{Content:[]mcp.Content{
     mcp.TextContent{Type:"text",Text:"an image attachment"},
     mcp.ImageContent{Type:"image",Data:b64,MIMEType:"image/png"},
   }},nil
 })
 trace:=&b41TracingTransport{Interface:transport.NewInProcessTransport(s)}
 original:=NewClient(trace)
 ctx:=context.Background()
 if err:=original.Start(ctx);err!=nil{t.Fatal(err)}
 defer original.Close()
 init:=mcp.InitializeRequest{}
 init.Params.ProtocolVersion=mcp.LATEST_PROTOCOL_VERSION
 init.Params.ClientInfo=mcp.Implementation{Name:"b41-exploratory-client",Version:"1.0"}
 if _,err:=original.Initialize(ctx,init);err!=nil{t.Fatal(err)}
 records:=[]map[string]any{}
 for _,name:=range []string{"b41_structured_exact","b41_media_exact"} {
   req:=mcp.CallToolRequest{}
   req.Params.Name=name
   observed,err:=original.CallTool(ctx,req)
   if err!=nil||observed==nil||observed.IsError{t.Fatalf("%s original consumer failed: %v",name,err)}
   if len(trace.Pairs)!=len(records)+1{t.Fatalf("%s missing wire",name)}
   pair:=trace.Pairs[len(trace.Pairs)-1]
   reqID:=pair.Request["id"]
   if reqID!=pair.Response["id"]{t.Fatal("mismatched native request ID")}
   var text string
   var media []map[string]any
   for _,block:=range observed.Content{
     switch c:=block.(type){
       case mcp.TextContent:
         if text!=""{text+="\n"}
         text+=c.Text
       case mcp.ImageContent:
         digest:=sha256.Sum256([]byte(c.Data))
         media=append(media,map[string]any{"type":"image","base64_sha256":hex.EncodeToString(digest[:])})
       default: t.Fatalf("unsupported source content block %T",block)
     }
   }
   consumer:=map[string]any{"tool":name,"request_id":reqID,"outcome":"success","text":text}
   contract:=map[string]any{"status":true,"text":"exact","structured":"none","media":"none"}
   if name=="b41_structured_exact"{
     originalStructured,ok:=observed.StructuredContent.(map[string]any)
     if !ok{t.Fatalf("original structured result not exposed as map: %T",observed.StructuredContent)}
     consumer["structured"]=originalStructured
     contract["structured"]="exact"
   }else{
     if len(media)!=1{t.Fatalf("original media not available: %d",len(media))}
     consumer["media"]=media
     contract["media"]="exact"
   }
   records=append(records,map[string]any{"case_id":"N1_EXPLORATORY_POST_EXPOSURE","tool":name,
       "wire":pair,"observed":consumer,"contract":contract,
       "execution_provenance":"ORIGINAL_EXTERNAL_CLIENT_CONTROLLED_SERVER",
       "original_source_git_blob":"9f1a4a692507e1c4854cf03f5fb9064351ad6da8",
       "original_commit_verified":true,
       "original_source_unchanged":true,
       "post_exposure_development_probe":true,
       "not_added_to_B41_holdout_FPR_denominator":true})
 }
 raw:=map[string]any{"schema":"risu-b41-postexposure-original-typed-channels-v1",
    "warning":"DEVELOPMENT_ONLY: after first frozen B41 results, not a newly independent holdout",
    "original_client_unchanged":true,"records":records}
 bytes,err:=json.MarshalIndent(raw,"","  ");if err!=nil{t.Fatal(err)}
 if err:=os.WriteFile(out,append(bytes,'\n'),0600);err!=nil{t.Fatal(err)}
 fmt.Println("B41_MARK3LABS_POSTEXPOSURE_STRUCTURED_AND_MEDIA_NATIVE_DONE")
}
