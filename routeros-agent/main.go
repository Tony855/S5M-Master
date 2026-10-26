package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	CentralURL string
	MachineCode string
	AgentSecret string
	RouterOSAddr string
	RouterOSUser string
	RouterOSPassword string
	TLSServerName string
	CAFile string
}
type Task struct {
	ID int64 `json:"id"`
	Action string `json:"action"`
	Params map[string]json.RawMessage `json:"params"`
}
type API struct { conn net.Conn }

var routerOSIDPattern = regexp.MustCompile("^\\*[0-9A-Fa-f]{1,31}$")
func env(key string) string { return strings.TrimSpace(os.Getenv(key)) }

func loadConfig() (Config, error) {
	c := Config{CentralURL:strings.TrimRight(env("S5M_CENTRAL_URL"),"/"), MachineCode:env("S5M_MACHINE_CODE"), AgentSecret:env("S5M_AGENT_SECRET"), RouterOSAddr:env("ROUTEROS_API_ADDR"), RouterOSUser:env("ROUTEROS_API_USERNAME"), RouterOSPassword:os.Getenv("ROUTEROS_API_PASSWORD"), TLSServerName:env("ROUTEROS_TLS_SERVER_NAME"), CAFile:env("ROUTEROS_CA_FILE")}
	u, err := url.Parse(c.CentralURL)
	if err != nil || u.Host=="" || u.User!=nil || u.RawQuery!="" || u.Fragment!="" || (u.Scheme!="https" && !(u.Scheme=="http" && (u.Hostname()=="localhost" || u.Hostname()=="127.0.0.1"))) { return c, errors.New("S5M_CENTRAL_URL must be HTTPS (HTTP is allowed only for localhost)") }
	if c.MachineCode=="" || c.AgentSecret=="" { return c, errors.New("S5M_MACHINE_CODE and S5M_AGENT_SECRET are required") }
	if c.RouterOSAddr=="" || c.RouterOSUser=="" || c.RouterOSPassword=="" { return c, errors.New("ROUTEROS_API_ADDR, ROUTEROS_API_USERNAME and ROUTEROS_API_PASSWORD are required") }
	host,port,err:=net.SplitHostPort(c.RouterOSAddr); if err!=nil || host=="" || port=="" { return c, errors.New("ROUTEROS_API_ADDR must be host:port, usually host:8729") }
	if _,err:=strconv.Atoi(port);err!=nil{return c,errors.New("ROUTEROS_API_ADDR port is invalid")}
	return c,nil
}
func request(client *http.Client, method, endpoint, token string, body []byte) (*http.Response,error) {
	req,err:=http.NewRequest(method,endpoint,bytes.NewReader(body)); if err!=nil{return nil,err}
	if token!=""{req.Header.Set("Authorization","Bearer "+token)}
	if body!=nil{req.Header.Set("Content-Type","application/json")}
	return client.Do(req)
}
func register(client *http.Client,c Config)(string,error){
	body,_:=json.Marshal(map[string]string{"machine_code":c.MachineCode,"secret":c.AgentSecret})
	resp,err:=request(client,http.MethodPost,c.CentralURL+"/api/v1/agent/register","",body);if err!=nil{return "",err};defer resp.Body.Close()
	if resp.StatusCode!=http.StatusOK{b,_:=io.ReadAll(io.LimitReader(resp.Body,2048));return "",fmt.Errorf("registration HTTP %d: %s",resp.StatusCode,strings.TrimSpace(string(b)))}
	var result struct{Token string `json:"token"`};if err:=json.NewDecoder(io.LimitReader(resp.Body,16<<10)).Decode(&result);err!=nil{return "",err};if result.Token==""{return "",errors.New("controller returned an empty agent token")};return result.Token,nil
}
func (c Config) tlsConfig()(*tls.Config,error){
	cfg:=&tls.Config{MinVersion:tls.VersionTLS12,ServerName:c.TLSServerName};if cfg.ServerName==""{host,_,_:=net.SplitHostPort(c.RouterOSAddr);cfg.ServerName=host}
	if c.CAFile!=""{pem,err:=os.ReadFile(c.CAFile);if err!=nil{return nil,err};roots,err:=x509.SystemCertPool();if err!=nil||roots==nil{roots=x509.NewCertPool()};if !roots.AppendCertsFromPEM(pem){return nil,errors.New("ROUTEROS_CA_FILE contains no valid CA certificate")};cfg.RootCAs=roots}
	return cfg,nil
}
func writeLength(w io.Writer,n int)error{
	var b [4]byte
	switch{case n<0x80:b[0]=byte(n);_,e:=w.Write(b[:1]);return e
	case n<0x4000:binary.BigEndian.PutUint16(b[:2],uint16(n)|0x8000);_,e:=w.Write(b[:2]);return e
	case n<0x200000:v:=uint32(n)|0xC00000;b[0]=byte(v>>16);b[1]=byte(v>>8);b[2]=byte(v);_,e:=w.Write(b[:3]);return e
	case n<0x10000000:binary.BigEndian.PutUint32(b[:],uint32(n)|0xE0000000);_,e:=w.Write(b[:]);return e
	default:b[0]=0xF0;binary.BigEndian.PutUint32(b[1:],uint32(n));_,e:=w.Write(b[:]);return e}
}
func readLength(r io.Reader)(int,error){
	var one [1]byte;if _,e:=io.ReadFull(r,one[:]);e!=nil{return 0,e};c:=one[0]
	switch{case c&0x80==0:return int(c),nil
	case c&0xC0==0x80:var b [1]byte;if _,e:=io.ReadFull(r,b[:]);e!=nil{return 0,e};return int(c&0x3F)<<8|int(b[0]),nil
	case c&0xE0==0xC0:var b [2]byte;if _,e:=io.ReadFull(r,b[:]);e!=nil{return 0,e};return int(c&0x1F)<<16|int(b[0])<<8|int(b[1]),nil
	case c&0xF0==0xE0:var b [3]byte;if _,e:=io.ReadFull(r,b[:]);e!=nil{return 0,e};return int(c&0x0F)<<24|int(b[0])<<16|int(b[1])<<8|int(b[2]),nil
	case c==0xF0:var b [4]byte;if _,e:=io.ReadFull(r,b[:]);e!=nil{return 0,e};n:=binary.BigEndian.Uint32(b[:]);if n>16<<20{return 0,errors.New("RouterOS API word exceeds 16 MiB")};return int(n),nil
	default:return 0,errors.New("invalid RouterOS API length prefix")}
}
func(a *API)writeSentence(words ...string)error{for _,word:=range words{if err:=writeLength(a.conn,len(word));err!=nil{return err};if _,err:=io.WriteString(a.conn,word);err!=nil{return err}};return writeLength(a.conn,0)}
func(a *API)readSentence()([]string,error){words:=make([]string,0,8);for{n,err:=readLength(a.conn);if err!=nil{return nil,err};if n==0{return words,nil};if n>1<<20{return nil,errors.New("RouterOS API word too large")};b:=make([]byte,n);if _,err:=io.ReadFull(a.conn,b);err!=nil{return nil,err};words=append(words,string(b))}}
func parseReply(words []string)map[string]string{row:=map[string]string{};for _,word:=range words{if strings.HasPrefix(word,"="){p:=strings.IndexByte(word[1:],'=');if p>=0{row[word[1:p+1]]=word[p+2:]}}};return row}
func(c Config)command(path string,args ...string)([]map[string]string,error){
	tc,err:=c.tlsConfig();if err!=nil{return nil,err};d:=&net.Dialer{Timeout:8*time.Second};conn,err:=tls.DialWithDialer(d,"tcp",c.RouterOSAddr,tc);if err!=nil{return nil,fmt.Errorf("connect RouterOS API-SSL: %w",err)};defer conn.Close();_ = conn.SetDeadline(time.Now().Add(15*time.Second));api:=&API{conn:conn}
	if err:=api.writeSentence("/login","=name="+c.RouterOSUser,"=password="+c.RouterOSPassword);err!=nil{return nil,err};login,err:=api.readSentence();if err!=nil{return nil,err};if len(login)>0&&login[0]=="!trap"{return nil,fmt.Errorf("RouterOS login rejected: %s",parseReply(login)["message"])};if len(login)==0||login[0]!="!done"{return nil,errors.New("unexpected RouterOS login response")}
	if err:=api.writeSentence(append([]string{path},args...)...);err!=nil{return nil,err};rows:=make([]map[string]string,0)
	for{reply,err:=api.readSentence();if err!=nil{return nil,fmt.Errorf("read RouterOS response: %w",err)};if len(reply)==0{continue};switch reply[0]{case "!re":rows=append(rows,parseReply(reply));case "!done":return rows,nil;case "!trap":m:=parseReply(reply)["message"];if m==""{m=strings.Join(reply," ")};return nil,fmt.Errorf("RouterOS %s: %s",path,m);case "!fatal":return nil,fmt.Errorf("RouterOS API fatal response: %s",strings.Join(reply," "))}}
}
func(c Config)execute(action string,params map[string]json.RawMessage)(map[string]any,error){
	switch action{
	case "routeros.container.list":rows,err:=c.command("/container/print","=.proplist=.id,name,remote-image,interface,root-dir,status,comment");if err!=nil{return nil,err};return map[string]any{"containers":rows,"count":len(rows)},nil
	case "routeros.container.start","routeros.container.stop","routeros.container.restart":
		raw,ok:=params["container_id"];if !ok{return nil,errors.New("container_id is required")};var id string;if json.Unmarshal(raw,&id)!=nil||!routerOSIDPattern.MatchString(id){return nil,errors.New("container_id must be a RouterOS internal ID such as *1")}
		paths:=[]string{"/container/start"};if action=="routeros.container.stop"{paths=[]string{"/container/stop"}};if action=="routeros.container.restart"{paths=[]string{"/container/stop","/container/start"}}
		for _,path:=range paths{if _,err:=c.command(path,"=.id="+id);err!=nil{return nil,err}};return map[string]any{"container_id":id,"action":action,"message":"RouterOS command completed"},nil
	default:return nil,fmt.Errorf("unsupported action %q",action)
	}
}
type agentCommand struct {
 ID string `json:"id"`
 Type string `json:"type"`
 ContainerID string `json:"container_id"`
}
func processAgentCommand(client *http.Client, c Config, token string) error {
 resp, err := request(client, http.MethodGet, c.CentralURL+"/api/v1/agent/command", token, nil)
 if err != nil { return err }; defer resp.Body.Close()
 if resp.StatusCode != http.StatusOK { b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048)); return fmt.Errorf("command poll HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b))) }
 var envelope struct { Command *agentCommand `json:"command"` }
 if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<10)).Decode(&envelope); err != nil { return err }; if envelope.Command == nil { return nil }
 cmd := envelope.Command
 actions := map[string]string{"routeros_container_list":"routeros.container.list", "routeros_container_start":"routeros.container.start", "routeros_container_stop":"routeros.container.stop", "routeros_container_restart":"routeros.container.restart"}
 action, ok := actions[cmd.Type]; if !ok { return ackAgentCommand(client, c, token, cmd.ID, "failed", "unsupported RouterOS command type: "+cmd.Type) }
 params := map[string]json.RawMessage{}; if cmd.ContainerID != "" { raw, _ := json.Marshal(cmd.ContainerID); params["container_id"] = raw }
 result, runErr := c.execute(action, params)
 status, message := "success", "RouterOS command completed"; if runErr != nil { status, message = "failed", runErr.Error() } else if result != nil { raw, err := json.Marshal(result); if err == nil { message = string(raw) } }
 if len(message) > 6000 { message = message[:6000] }
 if err := ackAgentCommand(client, c, token, cmd.ID, status, message); err != nil { return fmt.Errorf("ack RouterOS command: %w", err) }; if runErr != nil { return runErr }
 fmt.Printf("RouterOS command %s (%s) completed\n", cmd.ID, action); return nil
}
func ackAgentCommand(client *http.Client, c Config, token, id, status, message string) error {
 body, err := json.Marshal(map[string]string{"id":id, "status":status, "message":message}); if err != nil { return err }
 resp, err := request(client, http.MethodPost, c.CentralURL+"/api/v1/agent/command/ack", token, body); if err != nil { return err }; defer resp.Body.Close()
 if resp.StatusCode < 200 || resp.StatusCode >= 300 { b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048)); return fmt.Errorf("command ACK HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b))) }; return nil
}
func errorString(err error)string{if err==nil{return ""};return err.Error()}
func run()error{
	c,err:=loadConfig();if err!=nil{return err};client:=&http.Client{Timeout:20*time.Second};token,err:=register(client,c);if err!=nil{return fmt.Errorf("register with S5M: %w",err)}
	fmt.Printf("S5M RouterOS Agent registered as %s; API-SSL %s\n",c.MachineCode,c.RouterOSAddr)
	for{
		resourceRows, probeErr := c.command("/system/resource/print", "=.proplist=version,board-name,architecture-name,uptime")
		hostname := "routeros-" + c.MachineCode
		arch := "unknown"
		resource := map[string]string{}
		if len(resourceRows) > 0 {
			resource = resourceRows[0]
			if value := strings.TrimSpace(resource["architecture-name"]); value != "" {
				arch = value
			}
		}
		if identityRows, identityErr := c.command("/system/identity/print", "=.proplist=name"); identityErr == nil && len(identityRows) > 0 {
			if name := strings.TrimSpace(identityRows[0]["name"]); name != "" {
				hostname = name
			}
		} else if probeErr == nil && identityErr != nil {
			probeErr = fmt.Errorf("read RouterOS identity: %w", identityErr)
		}
		statusPayload, _ := json.Marshal(map[string]any{
			"hostname": hostname, "os": "routeros", "arch": arch,
			"docker_available": false, "mihomo_running": false, "mihomo_version": "",
			"status_json": map[string]any{
				"routeros_available": probeErr == nil, "routeros_api_addr": c.RouterOSAddr,
				"routeros_version": resource["version"], "board_name": resource["board-name"],
				"architecture_name": resource["architecture-name"], "uptime": resource["uptime"],
				"last_error": errorString(probeErr),
			},
		})
		resp,reqErr:=request(client,http.MethodPost,c.CentralURL+"/api/v1/agent/container/status",token,statusPayload);if reqErr==nil{io.Copy(io.Discard,io.LimitReader(resp.Body,1024));resp.Body.Close()}else{fmt.Printf("status report failed: %v\n",reqErr)}
		if err := processAgentCommand(client, c, token); err != nil { fmt.Printf("RouterOS command processing failed: %v\n", err) }
		time.Sleep(5*time.Second)
	}
}
func main(){if err:=run();err!=nil{fmt.Fprintln(os.Stderr,"S5M RouterOS Agent:",err);os.Exit(1)}}
