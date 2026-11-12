package s3_test

// Independent external historical guard regression, applied without modifying
// the actual implementations. No upstream fix-authored test is copied.
import (
 "fmt"
 "io"
 "net/http"
 "os"
 "strings"
 "sync"
 "testing"
 "github.com/overcast-sh/overcast/tests/helpers"
)
func risuWire(t *testing.T,s *helpers.TestServer,method,key string,body []byte,h map[string]string)(int,string,http.Header){
 t.Helper()
 var req *http.Request
 if method=="PUT"{req=put(s,"/risu-guard-bucket/"+key,body,h)}else{req=get(s,"/risu-guard-bucket/"+key)}
 r,e:=http.DefaultClient.Do(req);if e!=nil{t.Fatal(e)}
 b,e:=io.ReadAll(r.Body);r.Body.Close();if e!=nil{t.Fatal(e)}
 return r.StatusCode,string(b),r.Header
}
func risuStatus(t *testing.T,name string,actual,expected int){
 t.Helper();t.Logf("RISU_OUTCOME case=%s actual=%d expected=%d",name,actual,expected)
 if actual!=expected{t.Fatalf("case %s: %d want %d",name,actual,expected)}
}
func TestRISUBackendGuardHistory(t *testing.T){
 fixed:=os.Getenv("RISU_FIXED")=="1"
 srv:=helpers.NewTestServer(t);createBucket(t,srv,"risu-guard-bucket")
 t.Logf("RISU_VARIANT fixed=%v",fixed)
 t.Run("unconditional-control",func(t *testing.T){
  a,_,_:=risuWire(t,srv,"PUT","normal.txt",[]byte("first"),nil)
  b,_,_:=risuWire(t,srv,"PUT","normal.txt",[]byte("second"),nil)
  c,body,_:=risuWire(t,srv,"GET","normal.txt",nil,nil)
  risuStatus(t,"normal-first",a,200);risuStatus(t,"normal-overwrite",b,200);risuStatus(t,"normal-read",c,200)
  if body!="second"{t.Fatalf("lost normal update: %q",body)}
 })
 t.Run("absent-key-control",func(t *testing.T){
  status,_,_:=risuWire(t,srv,"PUT","absent.txt",[]byte("created"),map[string]string{"If-None-Match":"*"})
  risuStatus(t,"star-absent",status,200)
  _,body,_:=risuWire(t,srv,"GET","absent.txt",nil,nil)
  if body!="created"{t.Fatalf("creation lost %q",body)}
 })
 t.Run("existing-key-guard",func(t *testing.T){
  risuWire(t,srv,"PUT","existing.txt",[]byte("before"),nil)
  status,_,_:=risuWire(t,srv,"PUT","existing.txt",[]byte("overwrite"),map[string]string{"If-None-Match":"*"})
  want:=200;if fixed{want=412};risuStatus(t,"star-existing",status,want)
  _,body,_:=risuWire(t,srv,"GET","existing.txt",nil,nil)
  expected:="overwrite";if fixed{expected="before"}
  if body!=expected{t.Fatalf("state wrong %q want %q",body,expected)}
  t.Logf("RISU_STATE case=star-existing body=%q",body)
 })
 t.Run("matching-etag-control",func(t *testing.T){
  _,_,h:=risuWire(t,srv,"PUT","match.txt",[]byte("before"),nil)
  etag:=h.Get("ETag");if etag==""{t.Fatal("no ETag")}
  s,_,_:=risuWire(t,srv,"PUT","match.txt",[]byte("updated"),map[string]string{"If-Match":etag})
  risuStatus(t,"match-current",s,200)
  _,body,_:=risuWire(t,srv,"GET","match.txt",nil,nil)
  if body!="updated"{t.Fatalf("positive guard failed %q",body)}
 })
 t.Run("stale-etag-guard",func(t *testing.T){
  _,_,h:=risuWire(t,srv,"PUT","stale.txt",[]byte("one"),nil)
  etag:=h.Get("ETag");if etag==""{t.Fatal("no ETag")}
  risuWire(t,srv,"PUT","stale.txt",[]byte("two"),nil)
  s,_,_:=risuWire(t,srv,"PUT","stale.txt",[]byte("bad"),map[string]string{"If-Match":etag})
  want:=200;if fixed{want=412};risuStatus(t,"match-stale",s,want)
  _,body,_:=risuWire(t,srv,"GET","stale.txt",nil,nil)
  expected:="bad";if fixed{expected="two"}
  if body!=expected{t.Fatalf("stale write body %q want %q",body,expected)}
  t.Logf("RISU_STATE case=match-stale body=%q",body)
 })
 t.Run("missing-key-if-match",func(t *testing.T){
  s,_,_:=risuWire(t,srv,"PUT","missing.txt",[]byte("bad"),map[string]string{"If-Match":"\"00000000000000000000000000000000\""})
  want:=200;if fixed{want=404};risuStatus(t,"match-missing",s,want)
  status,body,_:=risuWire(t,srv,"GET","missing.txt",nil,nil)
  if fixed&&status!=404{t.Fatalf("should not have created %d %q",status,body)}
  if !fixed&&(status!=200||body!="bad"){t.Fatalf("historical write not observable %d %q",status,body)}
 })
 t.Run("read-guard-normal-control",func(t *testing.T){
  risuWire(t,srv,"PUT","read.txt",[]byte("present"),nil)
  r:=get(srv,"/risu-guard-bucket/read.txt")
  r.Header.Set("If-Match","\"00000000000000000000000000000000\"")
  resp,err:=http.DefaultClient.Do(r);if err!=nil{t.Fatal(err)};resp.Body.Close()
  risuStatus(t,"get-stale-condition",resp.StatusCode,412)
 })
 t.Run("concurrent-first-writer",func(t *testing.T){
  const n=16
  start:=make(chan struct{})
  codes:=make([]int,n);errs:=make([]error,n)
  var wg sync.WaitGroup;wg.Add(n)
  for i:=0;i<n;i++{go func(i int){defer wg.Done();<-start
    r:=put(srv,"/risu-guard-bucket/race.txt",[]byte(fmt.Sprintf("writer-%02d",i)),map[string]string{"If-None-Match":"*"})
    resp,e:=http.DefaultClient.Do(r);if e!=nil{errs[i]=e;return}
    codes[i]=resp.StatusCode;_,_=io.Copy(io.Discard,resp.Body);resp.Body.Close()
  }(i)}
  close(start);wg.Wait()
  counts:=map[int]int{}
  for i,code:=range codes{if errs[i]!=nil{t.Fatalf("request %d error %v",i,errs[i])};counts[code]++}
  winners,rejected:=counts[200],counts[412]
  t.Logf("RISU_RACE winners=%d rejects=%d total=%d",winners,rejected,n)
  if fixed&&(winners!=1||rejected!=15){t.Fatalf("patched mutual exclusion violated %v",counts)}
  if !fixed&&winners!=16{t.Fatalf("historical guard not ignored %v",counts)}
  status,body,_:=risuWire(t,srv,"GET","race.txt",nil,nil)
  if status!=200||!strings.HasPrefix(body,"writer-"){t.Fatalf("wrong final race state %d %q",status,body)}
 })
}
