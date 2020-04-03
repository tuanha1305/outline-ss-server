// Copyright 2018 Jigsaw Operations LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package shadowsocks

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/Jigsaw-Code/outline-ss-server/shadowsocks/slicepool"
	"github.com/shadowsocks/go-shadowsocks2/shadowaead"
)

// payloadSizeMask is the maximum size of payload in bytes.
const payloadSizeMask = 0x3FFF // 16*1024 - 1

// Maximum allowed cipher overhead
const maxCipherOverhead = 16

// The largest buffer we could need is for decrypting a max-length payload in
// shadowsocksWriter.
const maxBufferSize = 2 + maxCipherOverhead + payloadSizeMask + maxCipherOverhead

// Buffer pool used for encrypting and decrypting Shadowsocks streams.
var ssPool = slicepool.MakePool(maxBufferSize)

// Writer is an io.Writer that also implements io.ReaderFrom to
// allow for piping the data without extra allocations and copies.
type Writer interface {
	io.Writer
	io.ReaderFrom
}

type shadowsocksWriter struct {
	writer   io.Writer
	ssCipher shadowaead.Cipher
	// Wrapper for input that arrives as a slice.
	input bytes.Reader
	// Holds the first byte of each segment.
	firstByte [1]byte
	// These are lazily initialized:
	aead cipher.AEAD
	// Index of the next encrypted chunk to write.
	counter []byte
}

// NewShadowsocksWriter creates a Writer that encrypts the given Writer using
// the shadowsocks protocol with the given shadowsocks cipher.
func NewShadowsocksWriter(writer io.Writer, ssCipher shadowaead.Cipher) Writer {
	return &shadowsocksWriter{writer: writer, ssCipher: ssCipher}
}

// init generates a random salt, sets up the AEAD object and writes
// the salt to the inner Writer.
func (sw *shadowsocksWriter) init() (err error) {
	if sw.aead == nil {
		salt := make([]byte, sw.ssCipher.SaltSize())
		if _, err := io.ReadFull(rand.Reader, salt); err != nil {
			return fmt.Errorf("failed to generate salt: %v", err)
		}
		_, err := sw.writer.Write(salt)
		if err != nil {
			return fmt.Errorf("failed to write salt: %v", err)
		}
		sw.aead, err = sw.ssCipher.Encrypter(salt)
		if err != nil {
			return fmt.Errorf("failed to create AEAD: %v", err)
		}
		if sw.aead.Overhead() > maxCipherOverhead {
			return fmt.Errorf("Excessive cipher overhead (%d)", sw.aead.Overhead())
		}
		sw.counter = make([]byte, sw.aead.NonceSize())
	}
	return nil
}

// WriteBlock encrypts and writes the input buffer as one signed block.
func (sw *shadowsocksWriter) encryptBlock(ciphertext []byte, plaintext []byte) {
	sw.aead.Seal(ciphertext, sw.counter, plaintext, nil)
	increment(sw.counter)
}

func (sw *shadowsocksWriter) Write(p []byte) (int, error) {
	sw.input.Reset(p)
	n, err := sw.ReadFrom(&sw.input)
	return int(n), err
}

func (sw *shadowsocksWriter) ReadFrom(r io.Reader) (int64, error) {
	if err := sw.init(); err != nil {
		return 0, err
	}
	var written int64
	box := slicepool.MakeBox(&ssPool)
	for {
		// Read the first byte of a segment separately from the remaining bytes.
		// This allows us to release `buf` between segments.
		plaintextSize, err := r.Read(sw.firstByte[:])
		if plaintextSize > 0 {
			buf := box.Acquire()
			sizeBuf := buf[:2+sw.aead.Overhead()]
			payloadBuf := buf[len(sizeBuf):]
			payloadBuf[0] = sw.firstByte[0]
			plaintextSize, err = r.Read(payloadBuf[1:payloadSizeMask])
			plaintextSize++ // Account for first byte
			// big-endian payload size
			sizeBuf[0], sizeBuf[1] = byte(plaintextSize>>8), byte(plaintextSize)
			sw.encryptBlock(sizeBuf[:0], sizeBuf[:2])
			sw.encryptBlock(payloadBuf[:0], payloadBuf[:plaintextSize])
			payloadSize := plaintextSize + sw.aead.Overhead()
			_, writeErr := sw.writer.Write(buf[:len(sizeBuf)+payloadSize])
			// Don't hold onto the large buffer while waiting for the next segment.
			box.Release()
			if writeErr != nil {
				return written, fmt.Errorf("Failed to write payload: %v", writeErr)
			}
			written += int64(plaintextSize)
		}
		if err != nil {
			if errors.Is(err, io.EOF) { // ignore EOF as per io.ReaderFrom contract
				return written, nil
			}
			return written, fmt.Errorf("Failed to read payload: %v", err)
		}
	}
}

type shadowsocksReader struct {
	reader   io.Reader
	ssCipher shadowaead.Cipher
	// These are lazily initialized:
	aead cipher.AEAD
	// Index of the next encrypted chunk to read.
	counter []byte
	// Buffer for the uint16 size and its AEAD tag.  Made in init().
	size []byte
	// Holds a buffer for the payload and its AEAD tag, when needed.
	payload slicepool.Box
	// A view of any pending payload in `payload`.
	leftover []byte
}

// Reader is an io.Reader that also implements io.WriterTo to
// allow for piping the data without extra allocations and copies.
type Reader interface {
	io.Reader
	io.WriterTo
}

// NewShadowsocksReader creates a Reader that decrypts the given Reader using
// the shadowsocks protocol with the given shadowsocks cipher.
func NewShadowsocksReader(reader io.Reader, ssCipher shadowaead.Cipher) Reader {
	return &shadowsocksReader{
		reader:   reader,
		ssCipher: ssCipher,
		payload:  slicepool.MakeBox(&ssPool),
	}
}

// init reads the salt from the inner Reader and sets up the AEAD object
func (sr *shadowsocksReader) init() (err error) {
	if sr.aead == nil {
		// For chacha20-poly1305, SaltSize is 32, NonceSize is 12 and Overhead is 16.
		salt := make([]byte, sr.ssCipher.SaltSize())
		if _, err := io.ReadFull(sr.reader, salt); err != nil {
			return fmt.Errorf("failed to read salt: %w", err)
		}
		sr.aead, err = sr.ssCipher.Decrypter(salt)
		if err != nil {
			return fmt.Errorf("failed to create AEAD: %v", err)
		}
		if sr.aead.Overhead() > maxCipherOverhead {
			return fmt.Errorf("Excessive cipher overhead (%d)", sr.aead.Overhead())
		}
		sr.counter = make([]byte, sr.aead.NonceSize())
		sr.size = make([]byte, 2+sr.aead.Overhead())
	}
	return nil
}

// ReadBlock reads and decrypts a single signed block of ciphertext.
// The block must exactly match the size of `buf`.
// Returns an error only if the block could not be read.
func (sr *shadowsocksReader) readBlock(buf []byte) error {
	_, err := io.ReadFull(sr.reader, buf)
	if err != nil {
		return err
	}
	_, err = sr.aead.Open(buf[:0], sr.counter, buf, nil)
	increment(sr.counter)
	if err != nil {
		return fmt.Errorf("failed to decrypt: %v", err)
	}
	return nil
}

func (sr *shadowsocksReader) Read(b []byte) (int, error) {
	if err := sr.populateLeftover(); err != nil {
		if errors.Is(err, io.EOF) {
			// The Reader definition requires returning EOF itself.
			err = io.EOF
		}
		return 0, err
	}
	n := copy(b, sr.leftover)
	sr.drainLeftover(n)
	return n, nil
}

func (sr *shadowsocksReader) WriteTo(w io.Writer) (written int64, err error) {
	for {
		if err = sr.populateLeftover(); err != nil {
			if errors.Is(err, io.EOF) {
				err = nil
			}
			return
		}
		var n int
		n, err = w.Write(sr.leftover)
		written += int64(n)
		sr.drainLeftover(n)
		if err != nil {
			return
		}
	}
}

// Ensures that sr.leftover is nonempty.  If leftover is empty, this method
// waits for incoming data and decrypts it.
// Returns an error only if sr.leftover could not be populated.
func (sr *shadowsocksReader) populateLeftover() error {
	if len(sr.leftover) != 0 {
		return nil
	}
	if err := sr.init(); err != nil {
		return err
	}
	if err := sr.readBlock(sr.size); err != nil {
		return fmt.Errorf("failed to read payload size: %w", err)
	}
	size := (int(sr.size[0])<<8 + int(sr.size[1])) & payloadSizeMask
	payload := sr.payload.Acquire()
	if err := sr.readBlock(payload[:size+sr.aead.Overhead()]); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return fmt.Errorf("failed to read payload: %w", err)
	}
	sr.leftover = payload[:size]
	return nil
}

// Drains `n` bytes from sr.leftover, releasing the payload buffer when it
// is fully drained.
func (sr *shadowsocksReader) drainLeftover(n int) {
	sr.leftover = sr.leftover[n:]
	if len(sr.leftover) == 0 {
		sr.leftover = nil
		sr.payload.Release()
	}
}

// increment little-endian encoded unsigned integer b. Wrap around on overflow.
func increment(b []byte) {
	for i := range b {
		b[i]++
		if b[i] != 0 {
			return
		}
	}
}
