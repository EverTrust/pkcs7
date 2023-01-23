package pkcs7

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
)

// var encodeIndent = 0

type asn1Object interface {
	EncodeTo(writer *bytes.Buffer) error
}

type asn1Structured struct {
	tagBytes []byte
	content  []asn1Object
}

func (s asn1Structured) EncodeTo(out *bytes.Buffer) error {
	//fmt.Printf("%s--> tag: % X\n", strings.Repeat("| ", encodeIndent), s.tagBytes)
	//encodeIndent++
	inner := new(bytes.Buffer)
	for _, obj := range s.content {
		err := obj.EncodeTo(inner)
		if err != nil {
			return err
		}
	}
	//encodeIndent--
	out.Write(s.tagBytes)
	encodeLength(out, inner.Len())
	out.Write(inner.Bytes())
	return nil
}

type asn1Primitive struct {
	tagBytes []byte
	length   int
	content  []byte
}

func (p asn1Primitive) EncodeTo(out *bytes.Buffer) error {
	_, err := out.Write(p.tagBytes)
	if err != nil {
		return err
	}
	if err = encodeLength(out, p.length); err != nil {
		return err
	}
	//fmt.Printf("%s--> tag: % X length: %d\n", strings.Repeat("| ", encodeIndent), p.tagBytes, p.length)
	//fmt.Printf("%s--> content length: %d\n", strings.Repeat("| ", encodeIndent), len(p.content))
	out.Write(p.content)

	return nil
}

func ber2der(ber []byte) ([]byte, error) {
	if len(ber) == 0 {
		return nil, errors.New("ber2der: input ber is empty")
	}
	//fmt.Printf("--> ber2der: Transcoding %d bytes\n", len(ber))
	out := new(bytes.Buffer)

	//fmt.Printf("----->   Calling ber2der initial readObject  <------")
	obj, _, err := readObject(ber, 0)
	if err != nil {
		return nil, err
	}
	obj.EncodeTo(out)

	// if offset < len(ber) {
	//	return nil, fmt.Errorf("ber2der: Content longer than expected. Got %d, expected %d", offset, len(ber))
	//}

	return out.Bytes(), nil
}

// encodes lengths that are longer than 127 into string of bytes
func marshalLongLength(out *bytes.Buffer, i int) (err error) {
	n := lengthLength(i)

	for ; n > 0; n-- {
		err = out.WriteByte(byte(i >> uint((n-1)*8)))
		if err != nil {
			return
		}
	}

	return nil
}

// computes the byte length of an encoded length value
func lengthLength(i int) (numBytes int) {
	numBytes = 1
	for i > 255 {
		numBytes++
		i >>= 8
	}
	return
}

// encodes the length in DER format
// If the length fits in 7 bits, the value is encoded directly.
//
// Otherwise, the number of bytes to encode the length is first determined.
// This number is likely to be 4 or less for a 32bit length. This number is
// added to 0x80. The length is encoded in big endian encoding follow after
//
// Examples:
//  length | byte 1 | bytes n
//  0      | 0x00   | -
//  120    | 0x78   | -
//  200    | 0x81   | 0xC8
//  500    | 0x82   | 0x01 0xF4
//
func encodeLength(out *bytes.Buffer, length int) (err error) {
	if length >= 128 {
		l := lengthLength(length)
		err = out.WriteByte(0x80 | byte(l))
		if err != nil {
			return
		}
		err = marshalLongLength(out, length)
		if err != nil {
			return
		}
	} else {
		err = out.WriteByte(byte(length))
		if err != nil {
			return
		}
	}
	return
}

func readObject(ber []byte, offset int) (asn1Object, int, error) {
	// fmt.Printf("\n====> Starting readObject at offset: %d\n\n", offset)
	tagStart := offset
	b := ber[offset]
	offset++
	// fmt.Printf("BER TAG: %08b\n", b)
	tag := b & 0x1F // last 5 bits
	if tag == 0x1F {
		tag = 0
		for ber[offset] >= 0x80 {
			tag = tag*128 + ber[offset] - 0x80
			offset++
		}
		tag = tag*128 + ber[offset] - 0x80
		offset++
	}
	// fmt.Printf("ASN1 TAG: %d\n", tag)
	tagEnd := offset

	kind := b & 0x20
	if kind == 0 {
		debugprint("--> Primitive\n")
	} else {
		debugprint("--> Constructed\n")
	}
	// read length
	if offset >= len(ber) {
		return nil, 0, errors.New("ber2der: end of ber data reached")
	}
	var length int
	l := ber[offset]
	offset++
	indefinite := false
	if l > 0x80 {
		numberOfBytes := (int)(l & 0x7F)
		// fmt.Printf("numberOfBytes: %d l:%d\n", numberOfBytes, l)
		if numberOfBytes > 4 { // int is only guaranteed to be 32bit
			return nil, 0, errors.New("ber2der: BER tag length too long")
		}
		if numberOfBytes == 4 && (int)(ber[offset]) > 0x7F {
			return nil, 0, errors.New("ber2der: BER tag length is negative")
		}
		if 0x0 == (int)(ber[offset]) {
			return nil, 0, errors.New("ber2der: BER tag length has leading zero")
		}
		debugprint("--> (compute length) indicator byte: %x\n", l)
		debugprint("--> (compute length) length bytes: % X\n", ber[offset:offset+numberOfBytes])
		for i := 0; i < numberOfBytes; i++ {
			length = length*256 + (int)(ber[offset])
			offset++
		}
	} else if l == 0x80 {
		indefinite = true
	} else {
		length = (int)(l)
	}

	contentEnd := offset + length
	if contentEnd > len(ber) {
		return nil, 0, errors.New("ber2der: BER tag length is more than available data.")
	}
	var obj asn1Object
	if indefinite && kind == 0 {
		return nil, 0, errors.New("ber2der: Indefinite form tag must have constructed encoding")
	}
	if kind == 0 {
		obj = asn1Primitive{
			tagBytes: ber[tagStart:tagEnd],
			length:   length,
			content:  ber[offset:contentEnd],
		}
	} else {
		var subObjects []asn1Object
		for (offset < contentEnd) || indefinite {
			var subObj asn1Object
			var err error
			subObj, offset, err = readObject(ber, offset)
			if err != nil {
				return nil, 0, err
			}
			subObjects = append(subObjects, subObj)

			if indefinite {
				terminated, err := isIndefiniteTermination(ber, offset)
				if err != nil {
					return nil, 0, err
				}

				if terminated {
					break
				}
			}
		}
		obj = asn1Structured{
			tagBytes: ber[tagStart:tagEnd],
			content:  subObjects,
		}
	}

	// Apply indefinite form length with 0x0000 terminator.
	if indefinite {
		contentEnd = offset + 2
	}

	return obj, contentEnd, nil
}

func isIndefiniteTermination(ber []byte, offset int) (bool, error) {
	if len(ber)-offset < 2 {
		return false, errors.New("ber2der: Invalid BER format")
	}

	return bytes.Index(ber[offset:], []byte{0x0, 0x0}) == 0, nil
}

func parseHeader(data []byte) ([]byte, byte, int, error) {
	offset := 0
	header := []byte{data[offset]}
	b := data[offset]
	offset++
	debugprint("BER tag: %08b\n", b)
	tag := b & 0x1F // last 5 bits
	if tag == 0x1F {
		tag = 0
		for data[offset] >= 0x80 {
			tag = tag*128 + data[offset] - 0x80
			header = append(header, data[offset])
			offset++
		}
		tag = tag*128 + data[offset] - 0x80
		header = append(header, data[offset])
		offset++
	}
	debugprint("=> ASN.1 tag: %d\n", tag)
	kind := b & 0x20
	if kind == 0 {
		debugprint("--> Primitive\n")
	} else {
		debugprint("--> Constructed\n")
	}
	// computing length
	if offset >= len(data) {
		return nil, tag, 0, errors.New("ber2der: end of ber data reached")
	}
	var length int
	l := data[offset]
	header = append(header, l)
	offset++
	if l > 0x80 {
		numberOfBytes := (int)(l & 0x7F)
		if numberOfBytes > 4 { // int is only guaranteed to be 32bit
			return nil, tag, 0, errors.New("ber2der: BER tag length too long")
		}
		if numberOfBytes == 4 && (int)(data[offset]) > 0x7F {
			return nil, tag, 0, errors.New("ber2der: BER tag length is negative")
		}
		if 0x0 == (int)(data[offset]) {
			return nil, tag, 0, errors.New("ber2der: BER tag length has leading zero")
		}
		debugprint("--> (compute length) indicator byte: %x\n", l)
		debugprint("--> (compute length) length bytes: % X\n", data[offset:offset+numberOfBytes])
		for i := 0; i < numberOfBytes; i++ {
			length = length*256 + (int)(data[offset])
			header = append(header, data[offset])
			offset++
		}
		debugprint("--> (compute length) length: %d\n", length)
	} else if l == 0x80 {
		debugprint("Indefinite tag\n")
	} else {
		length = (int)(l)
	}
	if length > len(data) {
		return nil, tag, 0, errors.New("ber2der: BER tag length longer than available data")
	}
	return header, tag, length, nil
}

func readTag(data []byte, berExtTag bool) ([]byte, int, bool, []byte, error) {
	nullBytes := [2]byte{0, 0}
	headerArr := nullBytes
	copy(headerArr[:], data[:2])
	if headerArr == nullBytes {
		return data[:2], 0, false, data[2:], nil
	}
	header, tag, length, err := parseHeader(data)
	if err != nil {
		return nil, 0, false, nil, err
	}
	adjustLength := false
	if berExtTag && tag == 0x04 && length == 1000 {
		for index := range data {
			if index < length && index > len(header) && index < len(data)-1 && data[index] == header[0] && data[index+1] == header[1] {
				_, _, _, err = parseHeader(data[index:])
				if err == nil {
					length = index - len(header)
					adjustLength = true
					debugprint("=> Computing new length based on content: %d\n", length)
					break
				}
			}
		}
	}
	rest := data[len(header)+length:]
	debugprint("===> Header: %x\n", header)
	debugprint("===> Length: %d\n", length)
	//debugprint("===> Rest: %x\n", rest)
	return header, length, adjustLength, rest, nil
}

func buildHeader(b byte, l byte, length int) []byte {
	debugprint("===========> Length to build into header: %d\n", length)
	res := []byte{b}
	s := big.NewInt(int64(length))
	if l == 0x80 {
		// indefinite length, copy as is
		res = append(res, l)
	} else if length < 128 {
		// short length, short format
		res = append(res, s.Bytes()...)
	} else {
		// long length, long format
		nob := big.NewInt(int64(len(s.Bytes()) + 128))
		res = append(res, nob.Bytes()...)
		res = append(res, s.Bytes()...)
	}
	return res
}

func unMarshalBer(data []byte) ([]byte, error) {
	res := []byte{}
	berTagExt := false
	berOS := []byte{}
	// seems bouncy castle is using "1000" when it doesn't know which actual length to encode...
	BerOSMaxLength := 1000
	berOSLength := 0
	for len(data) > 0 {
		header, length, adjustLength, rest, err := readTag(data, berTagExt)
		if err != nil {
			return nil, err
		}
		if !berTagExt {
			debugprint("=> BerTagExt false, adding header\n")
			res = append(res, header...)
			if length > 0 {
				dataToAdd := data[len(header) : len(header)+length]
				res = append(res, dataToAdd...)
			}
		} else {
			debugprint("=> BerTagExt true, NOT adding header\n")
			berOS = append(berOS, data[len(header):len(header)+length]...)
			berOSLength += length
			debugprint("====> BerOS length: %d\n", berOSLength)
			if !adjustLength || berOSLength == BerOSMaxLength {
				debugprint("=> BerTagExt true and length was not adjusted, so now we have consumed all data. Data length will be %d\n", berOSLength)
				res = append(res, buildHeader(header[0], header[1], BerOSMaxLength)...)
				res = append(res, berOS...)
				//debugprint("berOS content: %x%x\n", buildHeader(header[0], header[1], berOSLength), berOS)
				if !adjustLength {
					berTagExt = false
				}
				berOS = []byte{}
				berOSLength = 0
			}
		}
		//debugprint("Header: %x\n", header)
		if header[0] == 0xa0 && header[1] == 0x80 && len(rest) > 2 && rest[0] == 0x04 && rest[1] == 0x82 {
			debugprint("Setting berTagExt to true\n")
			berTagExt = true
		}
		data = rest
	}
	return res, nil
}

func debugprint(format string, a ...interface{}) {
	fmt.Printf(format, a...)
}
