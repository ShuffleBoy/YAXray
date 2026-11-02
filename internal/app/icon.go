package app

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"math"
)

type iconKind int

const (
	iconOff iconKind = iota
	iconBusy
	iconOn
)

func inShield(x, y, w, top, bottom float64) bool {
	mid := top + (bottom-top)*0.45
	dx := math.Abs(x - 0.5)
	switch {
	case y < top || y > bottom:
		return false
	case y <= mid:
		return dx <= w
	default:
		t := (y - mid) / (bottom - mid)
		return dx <= w*math.Sqrt(1-t*t)
	}
}

func renderIcon(kind iconKind) []byte {
	const size, ss = 44, 4
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	for py := range size {
		for px := range size {
			hits := 0
			for sy := range ss {
				for sx := range ss {
					x := (float64(px) + (float64(sx)+0.5)/ss) / size
					y := (float64(py) + (float64(sy)+0.5)/ss) / size
					outer := inShield(x, y, 0.36, 0.06, 0.96)
					inner := inShield(x, y, 0.26, 0.15, 0.85)
					var on bool
					switch kind {
					case iconOn:
						on = outer && !onCheck(x, y)
					case iconBusy:
						on = (outer && !inner) || math.Hypot(x-0.5, y-0.45) < 0.09
					default:
						on = outer && !inner
					}
					if on {
						hits++
					}
				}
			}
			if hits > 0 {
				img.SetNRGBA(px, py, color.NRGBA{0, 0, 0, uint8(255 * hits / (ss * ss))})
			}
		}
	}
	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	return buf.Bytes()
}

func onCheck(x, y float64) bool {
	seg := func(ax, ay, bx, by float64) float64 {
		vx, vy := bx-ax, by-ay
		t := math.Max(0, math.Min(1, ((x-ax)*vx+(y-ay)*vy)/(vx*vx+vy*vy)))
		return math.Hypot(x-(ax+t*vx), y-(ay+t*vy))
	}
	const th = 0.055
	return seg(0.33, 0.47, 0.46, 0.60) < th || seg(0.46, 0.60, 0.68, 0.34) < th
}
