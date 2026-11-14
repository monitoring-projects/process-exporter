package diagnose

import (
	"math"
	"sort"
)

// fit is an ordinary least squares line y = a + b*x.
type fit struct {
	Slope, Intercept, R2 float64
	N                    int
}

// linfit returns the least squares fit and the coefficient of determination.
// A constant series has R2 = 0 (no explained variance), so it never qualifies
// as a trend.
func linfit(xs, ys []float64) fit {
	n := len(xs)
	if n < 2 || n != len(ys) {
		return fit{N: n}
	}
	var sx, sy float64
	for i := range xs {
		sx += xs[i]
		sy += ys[i]
	}
	mx, my := sx/float64(n), sy/float64(n)
	var sxx, sxy, syy float64
	for i := range xs {
		dx, dy := xs[i]-mx, ys[i]-my
		sxx += dx * dx
		sxy += dx * dy
		syy += dy * dy
	}
	if sxx == 0 || syy == 0 {
		return fit{Intercept: my, N: n}
	}
	b := sxy / sxx
	r := sxy / math.Sqrt(sxx*syy)
	return fit{Slope: b, Intercept: my - b*mx, R2: r * r, N: n}
}

// pearson returns the correlation coefficient of xs and ys (0 when undefined).
func pearson(xs, ys []float64) float64 {
	n := len(xs)
	if n < 3 || n != len(ys) {
		return 0
	}
	var sx, sy float64
	for i := range xs {
		sx += xs[i]
		sy += ys[i]
	}
	mx, my := sx/float64(n), sy/float64(n)
	var sxx, sxy, syy float64
	for i := range xs {
		dx, dy := xs[i]-mx, ys[i]-my
		sxx += dx * dx
		sxy += dx * dy
		syy += dy * dy
	}
	if sxx == 0 || syy == 0 {
		return 0
	}
	return sxy / math.Sqrt(sxx*syy)
}

func mean(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	var s float64
	for _, x := range v {
		s += x
	}
	return s / float64(len(v))
}

// cv is the coefficient of variation (stddev/mean), +Inf for a zero mean.
func cv(v []float64) float64 {
	m := mean(v)
	if m == 0 {
		return math.Inf(1)
	}
	var s float64
	for _, x := range v {
		s += (x - m) * (x - m)
	}
	return math.Sqrt(s/float64(len(v))) / math.Abs(m)
}

func percentile(v []float64, p float64) float64 {
	if len(v) == 0 {
		return 0
	}
	c := append([]float64(nil), v...)
	sort.Float64s(c)
	i := p * float64(len(c)-1)
	lo := int(math.Floor(i))
	hi := int(math.Ceil(i))
	return c[lo] + (c[hi]-c[lo])*(i-float64(lo))
}

// monotoneShare is the share of consecutive steps that do not decrease.
func monotoneShare(v []float64) float64 {
	if len(v) < 2 {
		return 0
	}
	up := 0
	for i := 1; i < len(v); i++ {
		if v[i] >= v[i-1] {
			up++
		}
	}
	return float64(up) / float64(len(v)-1)
}

func clamp01(x float64) float64 {
	if x < 0 {
		return 0
	}
	if x > 1 {
		return 1
	}
	return x
}
