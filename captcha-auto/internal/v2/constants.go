package v2

import (
	"errors"
	"image"
)

// vkAPIHost is the VK API host captcha requests go to.
const vkAPIHost = "api.vk.ru"

// sliderGuessV2 is one ranked candidate for a slider captcha.
type sliderGuessV2 struct {
	Index         int
	Swaps         []int
	Score         int64
	ScoreRGB      int64
	ScoreLuma     int64
	ScoreText     float64
	ConsensusRank int
}

type sliderPuzzleV2 struct {
	Image    image.Image
	Size     int
	Swaps    []int
	Attempts int
}

const captchaV2DeviceInfo = `{"screenWidth":1920,"screenHeight":1080,"screenAvailWidth":1920,"screenAvailHeight":1040,"innerWidth":1920,"innerHeight":970,"devicePixelRatio":1,"language":"ru-RU","languages":["ru-RU","ru","en-US","en"],"webdriver":false,"hardwareConcurrency":8,"notificationsPermission":"default"}`

// errCaptchaV2RateLimit is returned when VK caps the captcha session.
var errCaptchaV2RateLimit = errors.New("captcha session rate limit reached")

// errCaptchaV2Bot is returned when VK rejects a guess as bot-like.
var errCaptchaV2Bot = errors.New("captcha bot challenge")
