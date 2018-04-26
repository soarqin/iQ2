package main

import (
	"bufio"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"time"
	"os/signal"
	"encoding/json"
	"sync"
	"github.com/vbauerster/mpb"
	"io/ioutil"
	"net/url"
	"sort"
	"github.com/vbauerster/mpb/decor"
	"os/exec"
)

const workerCount = 4
const jobsFile = "jobs.json"

type request struct {
	req *http.Request
	res string
}

type j struct {
	Index int    `json:"index"`
	Url   string `json:"l"`
}

type downloadContext struct {
	fn, url string
}

var re = regexp.MustCompile("http:\\/\\/data\\.video\\.iqiyi\\.com\\/videos\\/v0\\/([0-9]+)\\/([0-9a-f]+)\\/([0-9a-f]+)\\/")
var requests = make([]request, 0)

type jslice []j

func (a jslice) Len() int           { return len(a) }
func (a jslice) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a jslice) Less(i, j int) bool { return a[i].Index < a[j].Index }

func main() {
	log.SetOutput(os.Stderr)
	if len(os.Args) <= 1 {
		listAdapters()
		return
	}

	if os.Args[1] == "r" {
		resume()
	} else {
		index, err := strconv.ParseInt(os.Args[1], 10, 32)
		if err != nil {
			log.Fatalln(err)
		}

		run(index)
	}
}

func listAdapters() {
	devs, _ := pcap.FindAllDevs()
	for idx, dev := range devs {
		fmt.Fprintf(os.Stderr, "%2v) %v %v\n", idx, dev.Name, dev.Description)
		for _, addr := range dev.Addresses {
			fmt.Fprintf(os.Stderr, "    %v\n", addr.IP)
		}
		fmt.Fprintln(os.Stderr)
	}
}

// httpStreamFactory implements tcpassembly.StreamFactory
type httpStreamFactory struct{}

// httpStream will handle the actual decoding of http requests.
type httpStream struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
}

func (h *httpStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	hstream := &httpStream{
		net:       net,
		transport: transport,
		r:         tcpreader.NewReaderStream(),
	}
	go hstream.run() // Important... we must guarantee that data from the reader stream is read.

	// ReaderStream implements tcpassembly.Stream, so we can return a pointer to it.
	return &hstream.r
}

func (h *httpStream) run() {
	buf := bufio.NewReader(&h.r)
	for {
		req, err := http.ReadRequest(buf)
		if err == io.EOF {
			// We must read until we see an EOF... very important!
			return
		} else if err != nil {
			log.Println("Error reading stream", h.net, h.transport, ":", err)
		} else {
			tcpreader.DiscardBytesToEOF(req.Body)
			req.Body.Close()
			if req.Method != http.MethodGet {
				continue
			}
			u := "http://" + req.Host + req.RequestURI
			res := re.FindStringSubmatch(u)
			if len(res) < 4 {
				tcpreader.DiscardBytesToEOF(req.Body)
				req.Body.Close()
				continue
			}
			nreq, _ := http.NewRequest(http.MethodGet, u, nil)
			for k, v := range req.Header {
				for _, v2 := range v {
					nreq.Header.Add(k, v2)
				}
			}
			requests = append(requests, request{nreq, res[1] + res[2] + res[3]})
		}
	}
}

func run(index int64) {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt)
	var handle *pcap.Handle
	var err error

	// Set up pcap packet capture
	devs, _ := pcap.FindAllDevs()
	for idx, dev := range devs {
		if int64(idx) == index {
			log.Printf("Starting capture on interface %s", dev.Name)
			handle, err = pcap.OpenLive(dev.Name, 4096, true, pcap.BlockForever)
			if err != nil {
				log.Fatalln(err)
			}
			break
		}
	}

	if err := handle.SetBPFFilter("tcp and dst port 80"); err != nil {
		log.Fatalln(err)
	}

	// Set up assembly
	streamFactory := &httpStreamFactory{}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	// Read in packets, pass to assembler.
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()
	ticker := time.Tick(time.Minute)
	for {
		select {
		case packet := <-packets:
			// A nil packet indicates the end of a pcap file.
			if packet == nil {
				return
			}
			if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
				log.Println("Unusable packet")
				continue
			}
			tcp := packet.TransportLayer().(*layers.TCP)
			assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)

		case <-ticker:
			// Every minute, flush connections that haven't seen activity in the past 2 minutes.
			assembler.FlushOlderThan(time.Now().Add(time.Minute * -2))

		case <-signals:
			handle.Close()
			signal.Reset(os.Interrupt)
			doDump()
			os.Exit(0)
		}
	}
}

func resume() {
	f, err := os.Open(jobsFile)
	if err != nil {
		log.Fatalln(err)
	}
	buf, err := ioutil.ReadAll(f)
	f.Close()
	if err != nil {
		log.Fatalln(err)
	}
	data := make(map[string]jslice)
	err = json.Unmarshal(buf, &data)
	if err != nil {
		log.Fatalln(err)
	}
	dumpFunc(data)
}

func doDump() {
	data := make(map[string]jslice)
	for _, req := range requests {
		resp, err := http.DefaultClient.Do(req.req)
		if err != nil {
			log.Fatalln(err)
		}
		rd, _ := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		jd := j{}
		err = json.Unmarshal(rd, &jd)
		if err != nil {
			log.Fatalln(err)
		}
		u, err := url.Parse(jd.Url)
		if err != nil {
			log.Fatalln(err)
		}
		jd.Index, err = strconv.Atoi(u.Query().Get("qd_index"))
		if err != nil {
			log.Fatalln(err)
		}
		key := req.res
		data[key] = append(data[key], jd)
	}
	j, err := json.Marshal(data)
	if err != nil {
		log.Fatalln(err)
	}
	f, err := os.Create(jobsFile)
	if err != nil {
		log.Fatalln(err)
	}
	f.Write(j)
	f.Close()
	dumpFunc(data)
}

func dumpFunc(data map[string]jslice) {
	for name, slices := range data {
		fmt.Printf("\nDumping files for %s\n", name)
		sort.Sort(slices)
		cfn := name + ".txt"
		c, _ := os.Create(cfn)
		lastIndex := 0
		var wg sync.WaitGroup
		p := mpb.New(mpb.WithWaitGroup(&wg))
		downloads := make([][2]string, 0)
		for _, v := range slices {
			if v.Index == lastIndex {
				fmt.Printf("!!!!WARNING: Duplicate index %d\n", lastIndex)
				continue
			}
			if v.Index != lastIndex+1 {
				fmt.Printf("!!!!WARNING: Missing index %d\n", lastIndex+1)
			}
			lastIndex = v.Index
			fn := fmt.Sprintf("%s_%d.f4v", name, v.Index)
			fmt.Fprintf(c, "file '%s'\n", fn)
			downloads = append(downloads, [2]string{fn, v.Url})
		}
		wg.Add(workerCount)
		downloadChan := make(chan *downloadContext, 256)
		for i := 0; i < workerCount; i++ {
			go downloadFunc(&wg, p, downloadChan)
		}
		for _, v := range downloads {
			downloadChan <- &downloadContext{v[0], v[1]}
		}
		close(downloadChan);
		p.Stop()
		c.Close()
		fname := name + ".mp4"
		fmt.Printf("->Merging to %s...", fname)
		exec.Command("ffmpeg", "-y", "-f", "concat", "-i", cfn, "-c", "copy", fname).Run()
		fmt.Println("finished")
	}
	os.Remove(jobsFile)
}

func downloadFunc(wg *sync.WaitGroup, p *mpb.Progress, dchan chan *downloadContext) {
	defer wg.Done()

	for {
		dc, ok := <-dchan
		if !ok {
			break
		}
		b := p.AddBar(100,
			mpb.PrependDecorators(
				decor.StaticName(dc.fn, 0, decor.DwidthSync|decor.DidentRight),
				decor.Elapsed(3, decor.DSyncSpace),
			),
			mpb.AppendDecorators(
				decor.CountersKiloByte("%.1f / %.1f", 10, decor.DSyncSpace),
				decor.StaticName("    ", 0, 0),
			),
		)
		doDownload(dc.fn, dc.url, b)
	}
}

func doDownload(fn, url string, b *mpb.Bar) {
	client := &http.Client{}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		log.Fatalln(err)
	}
	out, err := os.OpenFile(fn, os.O_RDWR | os.O_CREATE, 0666)
	if err != nil {
		log.Fatalln(err)
	}
	defer out.Close()
	off, err := out.Seek(0, io.SeekEnd)
	if err != nil {
		log.Fatalln(err)
	}
	if off > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", off))
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalln(err)
	}
	defer resp.Body.Close()

	b.SetTotal(int64(resp.ContentLength), true)
	if off > 0 {
		b.Incr(int(off))
	}

	cache := make([]byte, 65536)
	for {
		cnt, err := resp.Body.Read(cache)
		if cnt > 0 {
			out.Write(cache[0:cnt])
			b.Incr(cnt)
		}
		if err != nil {
			if err == io.EOF {
				b.Complete()
				break
			}
			log.Fatalln(err)
		}
	}
}
