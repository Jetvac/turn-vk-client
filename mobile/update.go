//go:build linux || android

package mobile

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/Jetvac/turn-vk-client/core/update"
)

func isAPK(name string) bool {
	return strings.HasPrefix(name, "TurnVK-") && strings.HasSuffix(name, ".apk")
}

// CheckUpdate returns the newer release than current as JSON (version,
// page, notes, asset_url...), or "" when current is the latest. It goes to
// GitHub: call it off the main thread.
func CheckUpdate(current string) (string, error) {
	r, err := update.Latest(context.Background(), current, isAPK)
	if err != nil || r == nil {
		return "", err
	}
	b, err := json.Marshal(r)
	return string(b), err
}

// DownloadUpdate saves the release (JSON from CheckUpdate) to dst, checked
// against the release's SHA256SUMS.txt. It blocks until done.
func DownloadUpdate(release, dst string) error {
	var r update.Release
	if err := json.Unmarshal([]byte(release), &r); err != nil {
		return err
	}
	return update.Download(context.Background(), &r, dst, nil)
}
