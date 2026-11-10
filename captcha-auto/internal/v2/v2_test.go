package v2

import (
	"context"
	"image"
	"image/color"
	"image/png"
	"strings"
	"testing"
)

func TestParseChallenge(t *testing.T) {
	c := ParseChallenge("https://id.vk.com/not_robot_captcha?session_token=abc123&domain=vk.com")
	if c == nil {
		t.Fatal("want non-nil challenge")
	}
	if c.SessionToken != "abc123" || c.RedirectURI == "" {
		t.Fatalf("bad parse: %+v", c)
	}
	if c.Domain() != "vk.com" {
		t.Fatalf("domain = %q, want vk.com", c.Domain())
	}
	if ParseChallenge("") != nil {
		t.Fatal("empty redirect URI should yield nil")
	}
}

func TestParseCaptchaV2Page(t *testing.T) {
	html := `
<html><body>
<script>
const powInput = "abc123";
const difficulty = 2;
window.init = {
  "data": {
    "show_captcha_type": "slider",
    "captcha_settings": [{"type":"slider","settings":"eyJzZWdtZXMiOiJ4eXkifQ=="}]
  }
};
</script>
<script src="https://id.vk.com/vkid/1.0.0/not_robot_captcha.js"></script>
</body></html>`
	page, err := parseCaptchaV2Page(html)
	if err != nil {
		t.Fatal(err)
	}
	if page.PowInput != "abc123" || page.PowDifficulty != 2 {
		t.Fatalf("pow not parsed: %+v", page)
	}
	if page.ScriptURL != "https://id.vk.com/vkid/1.0.0/not_robot_captcha.js" {
		t.Fatalf("script url = %q", page.ScriptURL)
	}
	if page.Init == nil || page.Init.Data.ShowCaptchaType != "slider" {
		t.Fatal("init not parsed")
	}
	if page.Init.Data.CaptchaSettings[0].Type != "slider" {
		t.Fatal("slider settings not parsed")
	}
}

func TestParseCaptchaV2PageNoPow(t *testing.T) {
	html := `<html><body><script>window.init={"data":{"show_captcha_type":"checkbox"}};</script></body></html>`
	page, err := parseCaptchaV2Page(html)
	if err != nil {
		t.Fatal(err)
	}
	if page.PowInput != "" {
		t.Fatalf("pow should be empty, got %q", page.PowInput)
	}
	if page.Init == nil {
		t.Fatal("init missing")
	}
}

func TestPoWSolves(t *testing.T) {
	// difficulty 1: one leading zero. Should find a nonce quickly.
	h := solveCaptchaPoWV2(context.Background(), "input", 1)
	if h == "" {
		t.Fatal("PoW failed to find a solution")
	}
	if !strings.HasPrefix(h, "0") {
		t.Fatalf("hash %q does not start with 0", h)
	}
}

func TestSplitSliderSteps(t *testing.T) {
	// Odd-length tail: the last element is the attempt count, the rest are swaps.
	size, swaps, attempts, err := splitSliderStepsV2([]int{3, 0, 1, 2, 7, 5})
	if err != nil {
		t.Fatal(err)
	}
	if size != 3 || len(swaps) != 4 || attempts != 5 {
		t.Fatalf("unexpected split: size=%d swaps=%v attempts=%d", size, swaps, attempts)
	}
}

func TestApplySliderSwaps(t *testing.T) {
	mapping, err := applySliderSwapsV2(3, []int{0, 1, 1, 2})
	if err != nil {
		t.Fatal(err)
	}
	// pairs (0,1),(1,2): [0,1,2] -> [1,2,0]
	if mapping[0] != 1 || mapping[1] != 2 || mapping[2] != 0 {
		t.Fatalf("unexpected mapping: %v", mapping)
	}
	if _, err := applySliderSwapsV2(3, []int{0, 1, 2}); err == nil {
		t.Fatal("odd-length swaps should error")
	}
}

// fakeImage builds a grid of distinct-colored tiles so the slider ranking has
// a clear, deterministic answer.
func fakeImageV2(size int) image.Image {
	img := image.NewRGBA(image.Rect(0, 0, size, size))
	for r := 0; r < size; r++ {
		for c := 0; c < size; c++ {
			img.SetRGBA(c, r, color.RGBA{R: uint8(c * 255 / size), G: uint8(r * 255 / size), B: 0, A: 255})
		}
	}
	return img
}

func TestRankSliderGuesses(t *testing.T) {
	size := 3
	img := fakeImageV2(size)
	swaps := []int{0, 1, 1, 2}
	guesses, err := rankSliderGuessesV2(img, size, swaps)
	if err != nil {
		t.Fatal(err)
	}
	if len(guesses) != 2 {
		t.Fatalf("want 2 candidates, got %d", len(guesses))
	}
	// The ranked list must be sorted by consensus rank ascending.
	for i := 1; i < len(guesses); i++ {
		if guesses[i].ConsensusRank < guesses[i-1].ConsensusRank {
			t.Fatalf("guesses not sorted: %+v", guesses)
		}
	}
}

func TestParseSliderPuzzleImageDecodes(t *testing.T) {
	size := 2
	img := fakeImageV2(size)
	var buf strings.Builder
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	// A real image payload must decode without error. This Go build's PNG
	// decoder returns *image.RGBA instead of *image.NRGBA, so accept either.
	img2, _, err := image.Decode(strings.NewReader(buf.String()))
	if err != nil {
		t.Fatal(err)
	}
	switch img2.(type) {
	case *image.NRGBA, *image.RGBA:
	default:
		t.Fatalf("decoded as %T", img2)
	}
}

func TestSliderCursorBuildsJSON(t *testing.T) {
	cursor := buildSliderCursorV2(1, 2)
	if !strings.HasPrefix(cursor, "[") || !strings.HasSuffix(cursor, "]") {
		t.Fatalf("cursor is not JSON array: %q", cursor)
	}
}
