package main

import (
	"bytes"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"golang.org/x/sys/unix"
	"log"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf tracepoint.c -- -I./headers

const MaxPathnameLength = 128

type bpfEvent struct {
	Pathname [MaxPathnameLength]uint8
}

// add custom data to token using the format specified at:
// https://docs.canarytokens.org/guide/dns-token.html#encoding-additional-information-in-your-token
// ```
// Base32 encode your data, and remove any padding '=' characters
// Insert periods (.) after every 63-bytes
// Append the magic string '.G'+<2-random-digits>+'.' (e.g. '.G12.' or '.G83.')
// ```
func hostnameWithPayload(hostname string, payload string, r *rand.Rand) string {
	if len(payload) == 0 {
		return hostname
	}
	data := []byte(payload)
	dst := make([]byte, base32.StdEncoding.EncodedLen(len(data)))
	base32.StdEncoding.Encode(dst, data)
	trimmed := strings.TrimRight(string(dst), "=")

	chunkSize := 63
	var sb strings.Builder
	for i, r := range []rune(trimmed) {
		sb.WriteRune(r)
		if i != 0 && i != 1 && (i+1)%chunkSize == 0 {
			sb.WriteRune('.')
		}
	}
	encodedPayloadWithSeparator := sb.String()

	magicString := fmt.Sprintf(".G%d%d", r.Intn(10), r.Intn(10))
	hostNameWithMagicString := strings.Join([]string{magicString, hostname}, ".")

	maxHostnameLength := 253
	maxPayloadSize := maxHostnameLength - len(hostNameWithMagicString)
	if len(encodedPayloadWithSeparator) <= maxPayloadSize {
		return encodedPayloadWithSeparator + hostNameWithMagicString
	}
	return encodedPayloadWithSeparator[0:maxPayloadSize] + hostNameWithMagicString
}

// send DNS requests
func consumer(canaryHostname string, link <-chan string, done chan<- bool) {
	rs := rand.NewSource(time.Now().UnixNano())
	r := rand.New(rs)

	for pathname := range link {
		log.Printf("triggering DNS token for: %s", pathname)
		base := filepath.Base(pathname)
		hostnameWithData := hostnameWithPayload(canaryHostname, base, r)
		_, err := net.LookupIP(hostnameWithData)
		if err != nil {
			fmt.Fprintf(os.Stderr, "DNS request failed: %v\n", err)
		}
	}
	done <- true
}

// read perf events
func producer(pathnames []string, rd *perf.Reader, link chan<- string) {
	watchedPathnames := map[string]struct{}{}
	for _, p := range pathnames {
		watchedPathnames[p] = struct{}{}
	}

	var event bpfEvent
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				close(link)
				return
			}
			log.Printf("reading from perf event reader: %s", err)
			continue
		}
		if record.LostSamples != 0 {
			log.Printf("perf event ring buffer full, dropped %d samples", record.LostSamples)
			continue
		}
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing perf event: %s", err)
			continue
		}
		pathname := unix.ByteSliceToString(event.Pathname[:])
		_, ok := watchedPathnames[pathname]
		if ok {
			log.Printf("read perf event value: %s", pathname)
			link <- pathname
		}
	}
	close(link)
}

func main() {
	// parse CLI flags
	var canaryHostname string
	flag.StringVar(&canaryHostname, "hostname", "", "DNS hostname to ping on events")
	var pathNames string
	flag.StringVar(&pathNames, "paths", "/usr/bin/id,/usr/bin/whoami,/usr/bin/hostname", "CSV; match `execve` syscalls with these pathnames as a first arg")
	flag.Parse()

	if len(canaryHostname) == 0 {
		log.Fatalf("hostname not set but required")
	}

	splitPathNames := strings.Split(pathNames, ",")
	for _, p := range splitPathNames {
		if len(p) > MaxPathnameLength {
			log.Fatalf("pathname too long: %s (%d chars)", p, len(p))
		}
	}

	// setup interrupt channel
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// eBPF setup prelude
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.BpfProg, nil)
	if err != nil {
		log.Fatalf("tracepoint uretprobe: %s", err)
	}
	defer tp.Close()

	rd, err := perf.NewReader(objs.Events, os.Getpagesize())
	if err != nil {
		log.Fatalf("creating perf event reader: %s", err)
	}
	defer rd.Close()

	// interrupt channel goroutine
	go func() {
		<-stopper
		log.Println("Received signal, exiting program..")

		if err := rd.Close(); err != nil {
			log.Fatalf("closing perf event reader: %s", err)
		}
	}()
	log.Printf("Listening for events..")

	// setup producer-consumer pattern
	link := make(chan string)
	done := make(chan bool)
	go producer(splitPathNames, rd, link)
	go consumer(canaryHostname, link, done)
	<-done
}
