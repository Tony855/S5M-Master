package main

import (
 "bytes"
 "encoding/json"
 "testing"
)

func TestRouterOSLengthRoundTrip(t *testing.T) {
 for _, n := range []int{0,1,127,128,255,16383,16384,65535,65536,0x1fffff,0x200000,0x0fffffff} {
  var b bytes.Buffer
  if err:=writeLength(&b,n);err!=nil { t.Fatal(err) }
  got,err:=readLength(&b)
  if err!=nil || got!=n { t.Fatalf("length %d round trip got %d err=%v",n,got,err) }
 }
}
func TestParseReply(t *testing.T) {
 got:=parseReply([]string{"!re","=.id=*1","=name=proxy","=status=running","=comment=contains=equals"})
 if got[".id"]!="*1" || got["name"]!="proxy" || got["status"]!="running" || got["comment"]!="contains=equals" { t.Fatalf("unexpected attributes: %#v",got) }
}
func TestRouterOSIDValidation(t *testing.T) {
 for _, id:=range []string{"*1","*AB12","*abcdef"} { if !routerOSIDPattern.MatchString(id) { t.Errorf("expected valid id %q",id) } }
 for _, id:=range []string{"","1","*","*1; /system reboot","*1/2","--"} { if routerOSIDPattern.MatchString(id) { t.Errorf("unexpected valid id %q",id) } }
}
func TestExecuteRequiresValidID(t *testing.T) {
 c:=Config{}
 for _, raw:=range []string{"{\"container_id\":\"*1; /system reboot\"}","{\"container_id\":\"name\"}","{}"} {
  var p map[string]json.RawMessage
  _ = json.Unmarshal([]byte(raw),&p)
  _,err:=c.execute("routeros.container.stop",p)
  if err==nil { t.Errorf("expected validation error for %s",raw) }
 }
}
