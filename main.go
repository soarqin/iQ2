package main

import (
	"encoding/json"
	"fmt"
	"github.com/vbauerster/mpb"
	"github.com/vbauerster/mpb/decor"
	"io"
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

type j struct {
	index int
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

type jslice []j

func (a jslice) Len() int           { return len(a) }
func (a jslice) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a jslice) Less(i, j int) bool { return a[i].index < a[j].index }

func main() {
	if len(os.Args) < 2 {
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
		jd.index, err = strconv.Atoi(u.Query().Get("qd_index"))
		if err != nil {
			panic(err)
		}
		key := res[1] + res[2] + res[3]
		data[key] = append(data[key], jd)
	}
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
			if v.index == lastIndex {
				fmt.Printf("!!!!WARNING: Duplicate index %d\n", lastIndex)
				continue
			}
			if v.index != lastIndex+1 {
				fmt.Printf("!!!!WARNING: Missing index %d\n", lastIndex+1)
			}
			lastIndex = v.index
			fn := fmt.Sprintf("%s_%d.f4v", name, v.index)
			fmt.Fprintf(c, "file '%s'\n", fn)
			downloads = append(downloads, [2]string{fn, v.Url})
		}
		wg.Add(len(downloads))
		for _, v := range downloads {
			fn := v[0]
			b := p.AddBar(100,
				mpb.PrependDecorators(
					decor.StaticName(fn, 0, decor.DwidthSync|decor.DidentRight),
					decor.Elapsed(3, decor.DSyncSpace),
				),
				mpb.AppendDecorators(
					decor.CountersKiloByte("%.1f / %.1f", 10, decor.DSyncSpace),
					decor.StaticName("    ", 0, 0),
				),
			)
			go downloadFunc(fn, v[1], &wg, b)
		}
		p.Stop()
		c.Close()
		fname := name + ".mp4"
		fmt.Printf("->Merging to %s...", fname)
		exec.Command("ffmpeg", "-y", "-f", "concat", "-i", cfn, "-c", "copy", fname).Run()
		fmt.Println("finished")
	}
}

func downloadFunc(fn string, url string, wg *sync.WaitGroup, b *mpb.Bar) {
	defer wg.Done()
	resp, err := http.Get(url)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	out, err := os.Create(fn)
	if err != nil {
		panic(err)
	}
	defer out.Close()

	b.SetTotal(int64(resp.ContentLength), true)

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
			panic(err)
		}
	}
}
