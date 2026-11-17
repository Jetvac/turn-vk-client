package split

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ListSources: where the list files are downloaded from, tried in turn
// (the file and its checksum always from the same place). The lists are
// rebuilt every 6 hours.
var ListSources = []string{
	"https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/",
	"https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/",
	"https://cdn.jsdelivr.net/gh/runetfreedom/russia-v2ray-rules-dat@release/",
}

const maxListFile = 300 << 20

// ListMinAge: a file this fresh is not checked again unless asked (the
// lists are rebuilt every 6 hours, and the site file is near 90 MB: not
// to download it twice a day over mobile data).
var ListMinAge = 3 * 24 * time.Hour

// NeededFiles: the files the rules' lists are in.
func NeededFiles(rules []ListRule) []string {
	var ip, site bool
	for _, r := range rules {
		if r.Off {
			continue
		}
		ip = ip || strings.HasPrefix(r.List, geoipPrefix)
		site = site || strings.HasPrefix(r.List, geositePrefix)
	}
	var out []string
	if ip {
		out = append(out, GeoIPFile)
	}
	if site {
		out = append(out, GeoSiteFile)
	}
	return out
}

// ListFile describes a downloaded file.
type ListFile struct {
	Name    string    `json:"name"`
	Size    int64     `json:"size"`
	Updated time.Time `json:"updated"`
}

// ListFiles describes the files in dir.
func ListFiles(dir string) []ListFile {
	var out []ListFile
	for _, n := range []string{GeoIPFile, GeoSiteFile} {
		if st, err := os.Stat(filepath.Join(dir, n)); err == nil {
			out = append(out, ListFile{n, st.Size(), st.ModTime()})
		}
	}
	return out
}

// ListClient is a way to the sources: Via names it in errors ("через VPN").
type ListClient struct {
	Via string
	C   *http.Client
}

// UpdateLists downloads the files that changed at the source, trying each
// client with each source in turn; changed lists the files replaced. A file
// is replaced only once it is whole and matches its checksum. Without
// force, files younger than ListMinAge are left alone.
func UpdateLists(ctx context.Context, dir string, files []string, force bool, clients ...ListClient) (changed []string, err error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	var errs []error
	for _, f := range files {
		if st, err := os.Stat(filepath.Join(dir, f)); err == nil && !force && time.Since(st.ModTime()) < ListMinAge {
			continue
		}
		var tries []string
		done := false
		for _, c := range clients {
			for _, src := range ListSources {
				ok, ferr := updateFile(ctx, c.C, src, dir, f)
				if ferr == nil {
					if ok {
						changed = append(changed, f)
					}
					done = true
					break
				}
				if ctx.Err() != nil {
					return changed, ctx.Err()
				}
				t := hostOfURL(src) + " — " + shortErr(ferr)
				if c.Via != "" {
					t = c.Via + ", " + t
				}
				tries = append(tries, t)
			}
			if done {
				break
			}
		}
		if !done {
			errs = append(errs, fmt.Errorf("%s не скачался (%s)", f, strings.Join(tries, "; ")))
		}
	}
	return changed, errors.Join(errs...)
}

func hostOfURL(s string) string {
	if u, err := url.Parse(s); err == nil && u.Host != "" {
		return u.Host
	}
	return s
}

// shortErr says what went wrong in a few words.
func shortErr(err error) string {
	var se statusError
	if errors.As(err, &se) {
		return "HTTP " + strconv.Itoa(int(se))
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "нет ответа"
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	s := err.Error()
	if len(s) > 80 {
		s = s[:80] + "…"
	}
	return s
}

type statusError int

func (e statusError) Error() string { return "HTTP " + strconv.Itoa(int(e)) }

func get(ctx context.Context, c *http.Client, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, statusError(resp.StatusCode)
	}
	return resp, nil
}

// updateFile: true when the file was replaced.
func updateFile(ctx context.Context, c *http.Client, src, dir, name string) (bool, error) {
	resp, err := get(ctx, c, src+name+".sha256sum")
	if err != nil {
		return false, err
	}
	line, _ := bufio.NewReader(io.LimitReader(resp.Body, 1024)).ReadString('\n')
	resp.Body.Close()
	want := strings.ToLower(strings.Fields(line + " ")[0])
	if len(want) != 64 {
		return false, errors.New("нет контрольной суммы")
	}
	path := filepath.Join(dir, name)
	sumPath := path + ".sha256"
	if have, err := os.ReadFile(sumPath); err == nil && strings.TrimSpace(string(have)) == want {
		if _, err := os.Stat(path); err == nil {
			return false, nil
		}
	}
	resp, err = get(ctx, c, src+name)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	tmp, err := os.CreateTemp(dir, name+".*.part")
	if err != nil {
		return false, err
	}
	defer os.Remove(tmp.Name())
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(resp.Body, maxListFile+1))
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return false, err
	}
	if n > maxListFile {
		return false, errors.New("файл слишком большой")
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		return false, errors.New("файл не совпал с контрольной суммой")
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return false, err
	}
	os.WriteFile(sumPath, []byte(want+"\n"), 0o644)
	return true, nil
}
