// Package update finds a newer TurnVK release on GitHub and downloads its
// file, checked against the release's SHA256SUMS.txt.
package update

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// Repo is where releases are published.
const Repo = "Jetvac/turn-vk-client"

// Release is a newer version and its file for this platform.
type Release struct {
	Version  string `json:"version"` // "0.4.0"
	Page     string `json:"page"`    // the release's web page
	Notes    string `json:"notes"`
	Asset    string `json:"asset"` // file name
	AssetURL string `json:"asset_url"`
	Size     int64  `json:"size"`
	SumsURL  string `json:"sums_url"`
}

// Client is used for GitHub's API and downloads.
var Client = &http.Client{Timeout: 10 * time.Minute}

// Latest returns the latest release when it is newer than current and has
// a file that match accepts, or nil.
func Latest(ctx context.Context, current string, match func(name string) bool) (*Release, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/repos/"+Repo+"/releases/latest", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "TurnVK-updater")
	resp, err := Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub: HTTP %d", resp.StatusCode)
	}
	var r struct {
		Tag    string `json:"tag_name"`
		URL    string `json:"html_url"`
		Body   string `json:"body"`
		Draft  bool   `json:"draft"`
		Pre    bool   `json:"prerelease"`
		Assets []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
			Size int64  `json:"size"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&r); err != nil {
		return nil, err
	}
	v := strings.TrimPrefix(r.Tag, "v")
	if r.Draft || r.Pre || !Newer(v, current) {
		return nil, nil
	}
	out := &Release{Version: v, Page: r.URL, Notes: r.Body}
	for _, a := range r.Assets {
		switch {
		case a.Name == "SHA256SUMS.txt":
			out.SumsURL = a.URL
		case match(a.Name) && out.AssetURL == "":
			out.Asset, out.AssetURL, out.Size = a.Name, a.URL, a.Size
		}
	}
	if out.AssetURL == "" {
		return nil, nil
	}
	return out, nil
}

// Newer reports whether version a is newer than b ("0.4.0" > "0.3.1"). A
// development build ("dev", "0.3.1-abc1234") counts as its base version;
// "dev" as the oldest.
func Newer(a, b string) bool {
	pa, pb := parts(a), parts(b)
	for i := range 3 {
		if pa[i] != pb[i] {
			return pa[i] > pb[i]
		}
	}
	return false
}

func parts(v string) [3]int {
	v = strings.TrimPrefix(v, "v")
	if i := strings.IndexAny(v, "-+ "); i >= 0 {
		v = v[:i]
	}
	var out [3]int
	for i, s := range strings.SplitN(v, ".", 3) {
		n, err := strconv.Atoi(s)
		if err != nil {
			return [3]int{}
		}
		out[i] = n
	}
	return out
}

// Download saves the release's file to dst, checked against
// SHA256SUMS.txt; progress (may be nil) gets the bytes so far.
func Download(ctx context.Context, r *Release, dst string, progress func(done, total int64)) error {
	if r.SumsURL == "" {
		return errors.New("the release has no SHA256SUMS.txt")
	}
	want, err := sum(ctx, r)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.AssetURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "TurnVK-updater")
	resp, err := Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download: HTTP %d", resp.StatusCode)
	}
	tmp := dst + ".part"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	h := sha256.New()
	var done int64
	buf := make([]byte, 64<<10)
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			if _, err := f.Write(buf[:n]); err != nil {
				f.Close()
				os.Remove(tmp)
				return err
			}
			h.Write(buf[:n])
			done += int64(n)
			if progress != nil {
				progress(done, r.Size)
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			f.Close()
			os.Remove(tmp)
			return rerr
		}
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		os.Remove(tmp)
		return fmt.Errorf("the downloaded file is damaged (SHA-256 %s, expected %s)", got[:12], want[:12])
	}
	os.Remove(dst)
	return os.Rename(tmp, dst)
}

// sum reads the asset's SHA-256 from SHA256SUMS.txt.
func sum(ctx context.Context, r *Release) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.SumsURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "TurnVK-updater")
	resp, err := Client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("SHA256SUMS.txt: HTTP %d", resp.StatusCode)
	}
	return parseSums(io.LimitReader(resp.Body, 64<<10), r.Asset)
}

func parseSums(rd io.Reader, name string) (string, error) {
	sc := bufio.NewScanner(rd)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == name && len(f[0]) == 64 {
			return strings.ToLower(f[0]), nil
		}
	}
	return "", fmt.Errorf("SHA256SUMS.txt has no line for %s", name)
}
