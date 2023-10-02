package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/wii-tools/lz11"
)

// Votes contains all the children structs needed to
// make a voting.bin file.
// type Votes struct {
// 	Header                   Header
// 	NationalQuestionTable    []QuestionInfo
// 	WorldWideQuestionTable   []QuestionInfo
// 	QuestionTextInfoTable    []QuestionTextInfo
// 	QuestionText             []QuestionText
// 	NationalResults          []NationalResult
// 	DetailedNationalResults  []DetailedNationalResult
// 	PositionEntryTable       []byte
// 	WorldwideResults         []WorldWideResult
// 	WorldwideResultsDetailed []DetailedWorldwideResult
// 	CountryInfoTable         []CountryInfoTable
// 	CountryTable             []uint16

// 	// Static values
// 	currentCountryCode  uint8
// 	tempDetailedResults []DetailedNationalResult
// }

// SQL variables.
var (
	pool     *pgxpool.Pool
	ctx      = context.Background()
	fileType FileType
	locality Locality
)

func checkError(err error) {
	if err != nil {
		log.Fatalf("Everybody Votes Channel file generator has encountered a fatal error! Reason: %v\n", err)
	}
}

func main() {
	// // var err error
	// var countryCode uint8 = 49

	// votes := Votes{}
	// votes.currentCountryCode = countryCode

	compressed, err := os.ReadFile("voting.bin")
	checkError(err)
	fmt.Println("voting.bin length", len(compressed))

	// wc24 is nonstandard and puts pkcs1v15 before data.
	n := len(compressed)
	for begin := 1; begin < n; begin++ {
		func() {
			defer func() {
				if x := recover(); x != nil {
					log.Printf("run time panic: %v", x)
				}
			}()

			buffer, err := lz11.Decompress(compressed[begin:])
			if err != nil {
				if err != lz11.ErrInvalidMagic {
					fmt.Println(begin, err)
				}
				return
			}

			fmt.Println("prefix length", begin, "decompressed length", len(buffer))

			err = os.WriteFile(fmt.Sprintf("voting-%d.bin", begin), buffer, 0644)
			checkError(err)
		}()
	}
}

// // DiscardPKCS1v15Signature extracts the PKCS1v15 signature length from a file
// // and discards the signature, returning the original data without the signature.
// func DiscardPKCS1v15Signature(filepath string) ([]byte, error) {
// 	// Read the file
// 	data, err := ioutil.ReadFile(filepath)
// 	if err != nil {
// 		return nil, err
// 	}

// 	// /usr/lib/go/src/crypto/rsa/pkcs1v15.go
// 	// 	crypto.SHA1:      {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14},
// 	// 15 bytes.

// 	// k := pub.Size()
// 	// if k < tLen+11 {
// 	// 	return ErrVerification
// 	// }

// 	// // RFC 8017 Section 8.2.2: If the length of the signature S is not k
// 	// // octets (where k is the length in octets of the RSA modulus n), output
// 	// // "invalid signature" and stop.
// 	// if k != len(sig) {
// 	// 	return ErrVerification
// 	// }

// 	// [ ] what's the WL24 public key?

// 	// Discard the signature and return the original data
// 	originalData := block.Bytes[:len(block.Bytes)-signatureLength]
// 	return originalData, nil
// }

// // Write writes the current values in Votes to an io.Writer method.
// // This is required as Go cannot write structs with non-fixed slice sizes,
// // but can write them individually.
// func (v *Votes) Write(writer io.Writer, data interface{}) {
// 	err := binary.Write(writer, binary.BigEndian, data)
// 	checkError(err)
// }

// func (v *Votes) WriteAll(writer io.Writer) {
// 	v.Write(writer, v.Header)

// 	// Questions
// 	v.Write(writer, v.NationalQuestionTable)
// 	v.Write(writer, v.WorldWideQuestionTable)
// 	v.Write(writer, v.QuestionTextInfoTable)

// 	// Go doesn't like nested slices in structs.
// 	for _, question := range v.QuestionText {
// 		v.Write(writer, question.Question)
// 		v.Write(writer, question.Response1)
// 		v.Write(writer, question.Response2)
// 	}

// 	// National Results
// 	v.Write(writer, v.NationalResults)
// 	v.Write(writer, v.DetailedNationalResults)
// 	v.Write(writer, v.PositionEntryTable)

// 	// Worldwide Results
// 	v.Write(writer, v.WorldwideResults)
// 	v.Write(writer, v.WorldwideResultsDetailed)

// 	v.Write(writer, v.CountryInfoTable)
// 	v.Write(writer, v.CountryTable)
// }

// // GetCurrentSize returns the current size of our Votes struct.
// // This is useful for calculating the current offset of Votes.
// func (v *Votes) GetCurrentSize() uint32 {
// 	buffer := bytes.NewBuffer([]byte{})
// 	v.WriteAll(buffer)

// 	return uint32(buffer.Len())
// }

// func SignFile(contents []byte) []byte {
// 	buffer := bytes.NewBuffer(nil)

// 	// Get RSA key and sign
// 	rsaData, err := ioutil.ReadFile("Private.pem")
// 	checkError(err)

// 	rsaBlock, _ := pem.Decode(rsaData)

// 	parsedKey, err := x509.ParsePKCS1PrivateKey(rsaBlock.Bytes)
// 	checkError(err)

// 	// Hash our data then sign
// 	hash := sha1.New()
// 	_, err = hash.Write(contents)
// 	checkError(err)

// 	contentsHashSum := hash.Sum(nil)

// 	reader := rand.Reader
// 	signature, err := rsa.SignPKCS1v15(reader, parsedKey, crypto.SHA1, contentsHashSum)
// 	checkError(err)

// 	buffer.Write(make([]byte, 64))
// 	buffer.Write(signature)
// 	buffer.Write(contents)

// 	return buffer.Bytes()
// }
