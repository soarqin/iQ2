package main

import (
	"encoding/json"
	"fmt"
	"github.com/vbauerster/mpb"
	"github.com/vbauerster/mpb/decor"
	"io"
    "log"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"sync"
)

const workerCount = 4
const jobsFile = "jobs.json"

type j struct {
    Index int    `json:"index"`
	Url   string `json:"l"`
}

type lroot struct {
	Log struct {
		Entries []struct {
			Request struct {
				Method  string `json:"method"`
				Url     string `json:"url"`
				Headers []struct {
					Name  string `json:"name"`
					Value string `json:"value"`
				} `json:"headers"`
			} `json:"request"`
		} `json:"entries"`
	} `json:"log"`
}

type downloadContext struct {
    fn, url string
}

type jslice []j

func (a jslice) Len() int           { return len(a) }
func (a jslice) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a jslice) Less(i, j int) bool { return a[i].Index < a[j].Index }

func main() {
	if len(os.Args) < 2 {
		return
	}
    if os.Args[1] == "r" {
        resume()
        return
    }
	cont, err := ioutil.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	re := regexp.MustCompile("https:\\/\\/data\\.video\\.iqiyi\\.com\\/videos\\/v0\\/([0-9]+)\\/([0-9a-f]+)\\/([0-9a-f]+)\\/")
	r := lroot{}
	json.Unmarshal(cont, &r)
	data := make(map[string]jslice)
	for _, ent := range r.Log.Entries {
		if ent.Request.Method != "GET" {
			continue
		}
		res := re.FindStringSubmatch(ent.Request.Url)
		if len(res) < 4 {
			continue
		}
		req, _ := http.NewRequest("GET", ent.Request.Url, nil)
		for _, v := range ent.Request.Headers {
			req.Header.Add(v.Name, v.Value)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			panic(err)
		}
		rd, _ := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		jd := j{}
		err = json.Unmarshal(rd, &jd)
		if err != nil {
			panic(err)
		}
		u, err := url.Parse(jd.Url)
		if err != nil {
			panic(err)
		}
		jd.Index, err = strconv.Atoi(u.Query().Get("qd_index"))
		if err != nil {
			panic(err)
		}
		key := res[1] + res[2] + res[3]
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
        close(downloadChan)
        p.Wait()
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
                decor.StaticName(dc.fn, decor.WC{W: 0, C: decor.DSyncWidth | decor.DidentRight}),
                decor.Elapsed(0, decor.WC{W: 3, C: decor.DSyncSpace}),
            ),
            mpb.AppendDecorators(
                decor.Counters(decor.UnitKiB, "% .1f / % .1f"),
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
    out, err := os.OpenFile(fn, os.O_RDWR|os.O_CREATE, 0666)
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

    if off > 0 {
        b.SetTotal(int64(resp.ContentLength+off), false)
        b.IncrBy(int(off))
    } else {
        b.SetTotal(int64(resp.ContentLength), false)
    }

    cache := make([]byte, 65536)
    for {
        cnt, err := resp.Body.Read(cache)
        if cnt > 0 {
            out.Write(cache[0:cnt])
            b.IncrBy(cnt)
        }
        if err != nil {
            if err == io.EOF {
                break
            }
            log.Fatalln(err)
        }
    }
}
