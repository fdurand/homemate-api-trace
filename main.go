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
	"math/rand"
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
	scenelist  = flag.Bool("scenelist", false, "Display scenes")
	scene      = flag.String("sceneID", "", "Scene Id to trigger")
	debug      = flag.Bool("debug", false, "Display debug")
)

// Client struct definition
type Client struct {
	UserName    string
	Password    string
	Keys        map[string]string
	ID          []byte
	Hashmd5     string
	UserID      string
	FamilyList  map[string]interface{}
	SiteDetails map[string]interface{}
	FamilyID    string
	tlsClient   *tls.Conn
	ctx         context.Context
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

type userDetails struct {
	UserID string  `json:"userId"`
	Type   float64 `json:"type"`
	Start  float64 `json:"start"`
	Limit  float64 `json:"limit"`
}

// UserDetails global struct
type UserDetails struct {
	defaultStruct
	userDetails
}

type homeDetails struct {
	DeviceFlag     float64 `json:"deviceFlag"`
	UserName       string  `json:"userName"`
	UserID         string  `json:"userId"`
	FamilyID       string  `json:"familyId"`
	LastUpdateTime float64 `json:"lastUpdateTime"`
	PageIndex      float64 `json:"pageIndex"`
	DataType       string  `json:"dataType"`
}

// HomeDetails global struct
type HomeDetails struct {
	defaultStruct
	homeDetails
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
func (c *Client) ExecuteScene(sceneID string) {
	scene := &ExecuteScene{
		defaultStruct{
			Serial:    float64(5.86385658e+08),
			Cmd:       float64(197),
			Ver:       "4.2.3.300",
			DebugInfo: "Android_ZhiJia365_27_4.2.3.300",
		},
		executeScene{
			SceneNo:     sceneID,
			TriggerType: float64(0),
			UserName:    c.UserName,
		},
	}
	c.marshal(scene)
}

// GetSession method to retreive the dynamic key
func (c *Client) GetSession() {
	session := &GetSession{
		defaultStruct{
			Serial:    randFloats(float64(1e+07), float64(9e+08)),
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

	c.marshal(session)
}

func randFloats(min, max float64) float64 {
	rand.Seed(time.Now().UnixNano())
	res := min + rand.Float64()*(max-min)
	Int64 := int(res)
	Number := []byte(strconv.Itoa(Int64))
	Combined := make([]byte, len(Number)+5)
	copy(Combined[0:1], Number[0:1])
	copy(Combined[1:2], []byte("."))
	copy(Combined[2:], Number[1:])
	copy(Combined[len(Number)+1:], []byte("e+0"+strconv.Itoa(len(Number)-1)))

	f, _ := strconv.ParseFloat(string(Combined), 64)
	return f
}

// Login method
func (c *Client) Login() {
	log := &Login{
		defaultStruct{
			Serial: randFloats(float64(1e+07), float64(9e+08)),
			// Serial:    float64(6.3553185e+07),
			Cmd:       float64(2),
			Ver:       "4.2.3.300",
			DebugInfo: "Android_ZhiJia365_27_4.2.3.300",
		},
		login{
			UserName: c.UserName,
			Password: c.Hashmd5,
			Type:     float64(4),
		},
	}
	c.marshal(log)
}

// UserDetails method to fetch the user details
func (c *Client) UserDetails() {
	user := &UserDetails{
		defaultStruct{
			Serial:    randFloats(float64(1e+07), float64(9e+08)),
			Cmd:       float64(201),
			Ver:       "4.2.3.300",
			DebugInfo: "Android_ZhiJia365_27_4.2.3.300",
		},
		userDetails{
			UserID: c.UserID,
			Type:   float64(0),
			Start:  float64(0),
			Limit:  float64(20),
		},
	}
	c.marshal(user)
}

// HomeDetails method to fetch the user details
func (c *Client) HomeDetails() {
	home := &HomeDetails{
		defaultStruct{
			Serial:    randFloats(float64(1e+07), float64(9e+08)),
			Cmd:       float64(147),
			Ver:       "4.2.3.300",
			DebugInfo: "Android_ZhiJia365_27_4.2.3.300",
		},
		homeDetails{
			UserID:         c.UserID,
			UserName:       c.UserName,
			FamilyID:       c.getFamilyID(),
			PageIndex:      float64(0),
			DeviceFlag:     float64(0),
			DataType:       "all",
			LastUpdateTime: float64(0),
		},
	}
	c.marshal(home)
}

// getFamilyID retreive the familyId attribute
func (c *Client) getFamilyID() string {
	if len(c.FamilyID) > 0 {
		return c.FamilyID
	}

	for k, v := range c.FamilyList {
		switch k {
		case "familyList":
			for _, w := range v.([]interface{}) {
				for m, x := range w.(map[string]interface{}) {
					switch m {
					case "familyId":
						c.FamilyID = x.(string)

					default:
					}
				}

			}
		default:
		}
	}
	return c.FamilyID
}

// getScenes retreive all the scenes
func (c *Client) getScenes() map[string]string {
	var scenes map[string]string
	scenes = make(map[string]string)
	var sceneNo string
	var sceneName string
	for k, v := range c.SiteDetails {
		switch k {
		case "scene":
			for _, w := range v.([]interface{}) {
				for m, x := range w.(map[string]interface{}) {
					switch m {
					case "sceneName":
						sceneName = x.(string)
					case "sceneNo":
						sceneNo = x.(string)
					default:
					}
				}
				scenes[sceneNo] = sceneName
			}
		default:
		}
	}
	return scenes
}

func (c *Client) marshal(object interface{}) {
	var payload []byte
	payload, err := json.Marshal(object)
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
				buf = make([]byte, 0, length)
				first = false
			}
			buf = append(buf, tmpbuf[:n]...)
		}
		if n < 512 {
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

	length := binary.BigEndian.Uint16(data[2:4])

	if *debug {
		if crc == calcrc {
			fmt.Print("CRC OK :" + strconv.Itoa(int(crc)) + "\n")
		} else {
			fmt.Print("CRC Error" + "\n")
		}
		fmt.Print("Magic : " + string(data[0:2]) + "\n")
		fmt.Print("Length : " + strconv.Itoa(int(length)) + "\n")
		fmt.Print("Type : " + string(data[4:6]) + "\n")
		fmt.Print("Id : " + string(data[10:42]) + "\n")
	}

	c.ID = data[10:42]

	decrypted := AESDecrypt(data[42:], []byte(c.Keys[string(data[4:6])]))
	json.Unmarshal(decrypted, &jsonResult)

	for k, v := range jsonResult {
		switch k {
		case "key":
			c.Keys["dk"] = v.(string)
		case "userId":
			c.UserID = v.(string)
		case "cmd":
			switch v.(float64) {
			case 201:
				c.FamilyList = jsonResult
			case 147:
				c.SiteDetails = jsonResult
			default:
			}

		default:
		}
	}
	if *debug {
		spew.Dump(jsonResult)
	}
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
	serverName := strings.Split(*server, ":")
	// Setup HTTPS client
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
		ServerName:   serverName[0],
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
	client.UserDetails()
	client.HomeDetails()
	if *scenelist {
		spew.Dump(client.getScenes())
	}
	if len(*scene) > 0 {
		client.ExecuteScene(*scene)
	}
}
