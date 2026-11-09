// P6-B10 source-original mcp-go stdio evidence upgrade for B9 GO1139.
// Build this synthetic test server at each exact pinned upstream source commit.
// No production endpoint, network client or real operator data.
package main

import (
  "context"
  "encoding/json"
  "log"
  "os"
  "github.com/mark3labs/mcp-go/mcp"
  "github.com/mark3labs/mcp-go/server"
)

func main() {
  s:=server.NewMCPServer("risu-public-synthetic-raw-schema","1.0.0",
    server.WithOutputSchemaValidation())
  in:=json.RawMessage(`{"type":"object","properties":{},"additionalProperties":false}`)
  out:=json.RawMessage(`{"type":"object","properties":{"temperature":{"type":"number"}},"required":["temperature"]}`)
  for _,tc:=range []struct{name string; value json.RawMessage}{
    {"bad_raw", json.RawMessage(`{"temperature":"not-a-number"}`)},
    {"good_raw", json.RawMessage(`{"temperature":21}`)},
  } {
    tc:=tc
    s.AddTool(mcp.Tool{Name:tc.name, RawInputSchema:in, RawOutputSchema:out},
      func(_ context.Context,_ mcp.CallToolRequest)(*mcp.CallToolResult,error){
        return &mcp.CallToolResult{
           Content:[]mcp.Content{mcp.NewTextContent("synthetic")},
           RawStructuredContent:tc.value,
        },nil
      })
  }
  if err:=server.ServeStdio(s);err!=nil {
    log.New(os.Stderr,"risu synthetic stdio: ",0).Println(err)
    os.Exit(1)
  }
}
