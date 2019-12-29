package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"hash/crc32"
	"io/ioutil"
	"log"
	"net"
	"strconv"

	"github.com/davecgh/go-spew/spew"
)

var (
	certFile   = flag.String("cert", "someCertFile", "A PEM eoncoded certificate file.")
	keyFile    = flag.String("key", "someKeyFile", "A PEM encoded private key file.")
	caFile     = flag.String("CA", "someCertCAFile", "A PEM eoncoded CA's certificate file.")
	username   = flag.String("username", "", "Homemate username")
	password   = flag.String("password", "", "Homemate password")
	primaryKey = flag.String("primarykey", "khggd54865SNJHGF", "Homemate primary key")
	server     = flag.String("Hostname", "homemate.orvibo.com:10002", "Server address:port to connect")
)

type Client struct {
	UserName  string
	Password  string
	Keys      map[string]string
	Id        []byte
	tlsClient *tls.Conn
	ctx       context.Context
}

type getSession struct {
	SysVersion      string `json:"sysVersion"`
	HardwareVersion string `json:"hardwareVersion"`
	Language        string `json:"language"`
	Source          string `json:"source"`
	Identifier      string `json:"identifier"`
	PhoneName       string `json:"phoneName"`
	SoftwareVersion string `json:"softwareVersion"`
}

type GetSession struct {
	defaultStruct
	getSession
}

type login struct {
	UserName string  `json:"userName"`
	Password string  `json:"password"`
	FamilyID string  `json:"familyId"`
	Type     float64 `json:"type"`
}

type executeScene struct {
	SceneNo     string  `json:"sceneNo"`
	UserName    string  `json:"userName"`
	TriggerType float64 `json:"triggerType"`
}

type defaultStruct struct {
	Cmd       float64 `json:"cmd"`
	Serial    float64 `json:"serial"`
	Ver       string  `json:"ver"`
	DebugInfo string  `json:"debugInfo"`
}

type Login struct {
	defaultStruct
	login
}

// NewClient constructor
func NewClient(context context.Context, username string, password string, primaryKey string) *Client {

	d := &Client{
		UserName: username,
		Password: password,
		ctx:      context,
	}
	d.Keys = make(map[string]string)
	d.Keys["pk"] = primaryKey
	d.Id = []byte{32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32}

	// d.tlsClient = tlsConnection()
	return d
}

func (c *Client) GetSession() {
	session := &GetSession{
		defaultStruct{
			Serial:    float64(7.38353548e+08),
			Cmd:       float64(0),
			Ver:       "4.2.3.300",
			DebugInfo: "Android_ZhiJia365_27_4.2.3.300",
		},
		getSession{
			SysVersion:      "Android8.1.0_27",
			Source:          "ZhiJia365",
			Identifier:      "ffffffff-8e69-cf94-0000-00007b1dd5c8",
			Language:        "fr",
			PhoneName:       "Nexus 5X",
			SoftwareVersion: "40203300",
			HardwareVersion: "LGE Nexus 5X",
		},
	}
	var payload []byte
	payload, err := json.Marshal(session)
	if err != nil {
		fmt.Print(err.Error())
	}
	c.Encode(payload)
}

func (c *Client) Login() {
	log := &Login{
		defaultStruct{
			Serial:    float64(6.3553185e+07),
			Cmd:       float64(2),
			Ver:       "4.2.3.300",
			DebugInfo: "Android_ZhiJia365_27_4.2.3.300",
		},
		login{
			UserName: c.UserName,
			Password: c.Password,
			FamilyID: "49ed7e5b91dd45c8af8cb37d3e4e1234",
			Type:     float64(4),
		},
	}
	var payload []byte
	payload, err := json.Marshal(log)
	if err != nil {
		fmt.Print(err.Error())
	}
	c.Encode(payload)
}

func (c *Client) returnKey() string {
	if val, ok := c.Keys["dk"]; ok {
		return val
	}
	return c.Keys["pk"]
}

func (c *Client) Encode(payload []byte) {
	encrypted := AESEncrypt(payload, []byte(c.returnKey()))
	c.Header(encrypted)
}

func (c *Client) Header(payload []byte) {
	Packet := make([]byte, len(payload)+42)
	copy(Packet[0:2], []byte("hd"))
	binary.BigEndian.PutUint16(Packet[2:4], uint16(len(payload)+42))
	copy(Packet[4:6], []byte("dk"))
	calcrc := crc32.ChecksumIEEE(payload)
	binary.BigEndian.PutUint32(Packet[6:10], calcrc)
	copy(Packet[10:42], c.Id)
	copy(Packet[42:], payload)

	_, err := c.tlsClient.Write(Packet)
	if err != nil {
		fmt.Print(err.Error())
	}

}

func (c *Client) Decode(data []byte) {
	var jsonResult map[string]interface{}
	// var merge bool
	// if merge {
	// 	data = append(previousData, data...)
	// }

	calcrc := crc32.ChecksumIEEE(data[42:])
	crc := binary.BigEndian.Uint32(data[6:10])

	if crc == calcrc {
		// merge = false
		fmt.Print("CRC OK :" + strconv.Itoa(int(crc)) + "\n")
		// way++
	} else {
		// merge = true
		// previousData = data
		fmt.Print("CRC Error" + "\n")
		// continue
	}

	fmt.Print("Magic : " + string(data[0:2]) + "\n")
	length := binary.BigEndian.Uint16(data[2:4])
	fmt.Print("Length : " + strconv.Itoa(int(length)) + "\n")
	fmt.Print("Type : " + string(data[4:6]) + "\n")
	fmt.Print("Id : " + string(data[10:42]) + "\n")
	c.Id = data[10:42]
	fmt.Print("Payload Type : " + string(data[4]) + "\n")
	spew.Dump([]byte(c.Keys[string(data[4:6])]))
	decrypted := AESDecrypt(data[42:], []byte(c.Keys[string(data[4:6])]))
	json.Unmarshal(decrypted, &jsonResult)

	// Update Dynamic Key
	for k, v := range jsonResult {
		switch k {
		case "key":
			c.Keys["dk"] = v.(string)
		default:
		}
	}
	spew.Dump(jsonResult)
}

func tlsConnection() *tls.Conn {
	// Load client cert
	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		log.Fatal(err)
	}

	// Load CA cert
	caCert, err := ioutil.ReadFile(*caFile)
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Setup HTTPS client
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}
	tlsConfig.BuildNameToCertificate()

	conn, err := net.Dial("tcp", *server)
	if err != nil {
		fmt.Print("Error " + err.Error())
	}

	return tls.Client(conn, tlsConfig)
}

func main() {

	flag.Parse()
	var ctx = context.Background()

	client := NewClient(ctx, *username, *password, *primaryKey)
	client.GetSession()
}
