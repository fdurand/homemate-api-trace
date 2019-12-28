package main

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"hash/crc32"
	"log"
	"os"
	"regexp"
	"strconv"
)

func main() {
	file := flag.String("file", "", "File to parse")
	password := flag.String("password", "", "Password of the primary key")

	flag.Parse()

	var way int
	way = 0

	var client string

	var m map[string]string
	m = make(map[string]string)
	m["pk"] = *password

	dat, err := os.Open(*file)

	defer dat.Close()
	if err != nil {
		fmt.Print("error")
	}
	var previousData []byte
	r, _ := regexp.Compile("(^\\s*[0-9a-f]+$)")
	space, _ := regexp.Compile("\\s+")
	scanner := bufio.NewScanner(dat)
	var merge bool

	for scanner.Scan() {
		if r.MatchString(scanner.Text()) {
			var jsonResult map[string]interface{}
			result := space.ReplaceAllString(scanner.Text(), "")
			data, _ := hex.DecodeString(result)
			if merge {
				data = append(previousData, data...)
			}
			if Even(way) {
				client = "Client"
			} else {
				client = "server"
			}

			calcrc := crc32.ChecksumIEEE(data[42:])
			crc := binary.BigEndian.Uint32(data[6:10])

			if crc == calcrc {
				merge = false
				fmt.Print("CRC OK :" + strconv.Itoa(int(crc)) + "\n")
				way++
			} else {
				// Need to append next packet
				merge = true
				previousData = data
				fmt.Print("CRC Error" + "\n")
				continue
			}

			fmt.Print("Client : " + client + "\n")
			fmt.Print("Magic : " + string(data[0:2]) + "\n")
			length := binary.BigEndian.Uint16(data[2:4])
			fmt.Print("Length : " + strconv.Itoa(int(length)) + "\n")
			fmt.Print("Type : " + string(data[4:6]) + "\n")
			fmt.Print("Id : " + string(data[10:42]) + "\n")
			fmt.Print("Payload Type : " + string(data[4]) + "\n")

			decrypted := AESDecrypt(data[42:], []byte(m[string(data[4:6])]))
			json.Unmarshal(decrypted, &jsonResult)

			// Update Dynamic Key
			for k, v := range jsonResult {
				switch k {
				case "key":
					m["dk"] = v.(string)
				default:

				}
			}
			spew.Dump(jsonResult)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

}

func Even(number int) bool {
	return number%2 == 0
}

func Odd(number int) bool {
	return !Even(number)
}
