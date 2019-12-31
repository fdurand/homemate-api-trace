package main

import (
	"context"
	"crypto/md5"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"hash/crc32"
	"io"
	"io/ioutil"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

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

// Client struct definition
type Client struct {
	UserName  string
	Password  string
	Keys      map[string]string
	ID        []byte
	Hashmd5   string
	UserID    string
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

// GetSession global struct
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

// Login global struct
type Login struct {
	defaultStruct
	login
}

type executeScene struct {
	SceneNo     string  `json:"sceneNo"`
	UserName    string  `json:"userName"`
	TriggerType float64 `json:"triggerType"`
}

// ExecuteScene global struct
type ExecuteScene struct {
	defaultStruct
	executeScene
}

type defaultStruct struct {
	Cmd       float64 `json:"cmd"`
	Serial    float64 `json:"serial"`
	Ver       string  `json:"ver"`
	DebugInfo string  `json:"debugInfo"`
}

// NewClient constructor
func NewClient(context context.Context, username string, password string, primaryKey string) *Client {

	c := &Client{
		UserName: username,
		Password: password,
		ctx:      context,
	}
	c.Keys = make(map[string]string)
	c.Keys["pk"] = primaryKey
	c.ID = []byte{32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32}

	hasher := md5.New()
	hasher.Write([]byte(password))
	c.Hashmd5 = strings.ToUpper(hex.EncodeToString(hasher.Sum(nil)))

	c.tlsClient = tlsConnection()

	return c
}

// ExecuteScene method to execute a scene
func (c *Client) ExecuteScene() {
	scene := &ExecuteScene{
		defaultStruct{
			Serial:    float64(5.86385658e+08),
			Cmd:       float64(197),
			Ver:       "4.2.3.300",
			DebugInfo: "Android_ZhiJia365_27_4.2.3.300",
		},
		executeScene{
			SceneNo:     "55d15b93f1c14898beab783de1b8af89",
			TriggerType: float64(0),
			UserName:    c.UserName,
		},
	}
	var payload []byte
	payload, err := json.Marshal(scene)
	if err != nil {
		fmt.Print(err.Error())
	}

	c.Encode(payload)
}

// GetSession method to retreive the dynamic key
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

// Login method
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
			Password: c.Hashmd5,
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

func (c *Client) returnKeyType() string {
	if _, ok := c.Keys["dk"]; ok {
		return "dk"
	}
	return "pk"
}

// Encode encrypt the payload
func (c *Client) Encode(payload []byte) {
	encrypted := AESEncrypt(payload, []byte(c.returnKey()))
	c.Header(encrypted)
}

// Header add the header of the encrypted payload
func (c *Client) Header(payload []byte) {
	Packet := make([]byte, len(payload)+42)
	copy(Packet[0:2], []byte("hd"))
	binary.BigEndian.PutUint16(Packet[2:4], uint16(len(payload)+42))
	copy(Packet[4:6], []byte(c.returnKeyType()))
	calcrc := crc32.ChecksumIEEE(payload)
	binary.BigEndian.PutUint32(Packet[6:10], calcrc)
	copy(Packet[10:42], c.ID)
	copy(Packet[42:], payload)

	c.Decode(Packet)

	c.Send(Packet)
}

// Send on the wire
func (c *Client) Send(data []byte) {
	first := true
	n, err := c.tlsClient.Write(data)
	if err != nil {
		fmt.Print(err.Error())
	}
	var buf []byte
	tmpbuf := make([]byte, 512)
	for {
		n, err = c.tlsClient.Read(tmpbuf)

		if err != nil {
			if err != io.EOF {
				fmt.Println("read error:", err)
			}
			break
		}
		if n > 0 {
			if first {
				length := binary.BigEndian.Uint16(tmpbuf[2:4])
				buf = make([]byte, 0, length) // big buffer
				first = false
			}
			buf = append(buf, tmpbuf[:n]...)
		}
		if n <= 512 {
			break
		}
	}

	c.Decode(buf)
}

// Decode the packet and the header
func (c *Client) Decode(data []byte) {
	var jsonResult map[string]interface{}

	calcrc := crc32.ChecksumIEEE(data[42:])
	crc := binary.BigEndian.Uint32(data[6:10])

	if crc == calcrc {
		fmt.Print("CRC OK :" + strconv.Itoa(int(crc)) + "\n")
	} else {
		fmt.Print("CRC Error" + "\n")
	}

	fmt.Print("Magic : " + string(data[0:2]) + "\n")
	length := binary.BigEndian.Uint16(data[2:4])
	fmt.Print("Length : " + strconv.Itoa(int(length)) + "\n")
	fmt.Print("Type : " + string(data[4:6]) + "\n")
	fmt.Print("Id : " + string(data[10:42]) + "\n")
	c.ID = data[10:42]

	decrypted := AESDecrypt(data[42:], []byte(c.Keys[string(data[4:6])]))
	json.Unmarshal(decrypted, &jsonResult)

	// Update Dynamic Key
	for k, v := range jsonResult {
		switch k {
		case "key":
			c.Keys["dk"] = v.(string)
		case "userId":
			c.UserID = v.(string)
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
		ServerName:   "homemate.orvibo.com",
	}
	tlsConfig.BuildNameToCertificate()

	conn, err := net.Dial("tcp", *server)
	if err != nil {
		fmt.Print("Error " + err.Error())
	}
	TLS := tls.Client(conn, tlsConfig)
	// TLS.SetReadDeadline(time.Now().Add(1 * time.Second))
	TLS.SetDeadline(time.Now().Add(4 * time.Second))
	return TLS
}

func main() {

	flag.Parse()
	var ctx = context.Background()

	client := NewClient(ctx, *username, *password, *primaryKey)
	client.GetSession()
	client.Login()
	client.ExecuteScene()
}
