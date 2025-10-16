package blockchain

import (
	"math"
	"sort"
	"sync"
	"time"
)

//medianTime 就是 btcd 的**“去中心化闹钟”**：
//把所有节点报来的时间做中位数过滤，再限制在 ±70 分钟内，最终给区块链共识一个可信的“现在几点”。

const (
	// maxAllowedOffsetSeconds is the maximum number of seconds in either
	// direction that local clock will be adjusted.  When the median time
	// of the network is outside of this range, no offset will be applied.
	maxAllowedOffsetSecs = 70 * 60 // 1 hour 10 minutes

	// similarTimeSecs is the number of seconds in either direction from the
	// local clock that is used to determine that it is likely wrong and
	// hence to show a warning.
	similarTimeSecs = 5 * 60 // 5 minutes
)

var (
	// maxMedianTimeEntries is the maximum number of entries allowed in the
	// median time data.  This is a variable as opposed to a constant so the
	// test code can modify it.
	maxMedianTimeEntries = 200
)

type MedianTimeSource interface {
	// AdjustedTime returns the current time adjusted by the median time
	// offset as calculated from the time samples added by AddTimeSample.
	AdjustedTime() time.Time

	// AddTimeSample adds a time sample that is used when determining the
	// median time of the added samples.
	AddTimeSample(id string, timeVal time.Time)

	// Offset returns the number of seconds to adjust the local clock based
	// upon the median of the time samples added by AddTimeData.
	Offset() time.Duration
}

// int64Sorter implements sort.Interface to allow a slice of 64-bit integers to
// be sorted.
type int64Sorter []int64

// Len returns the number of 64-bit integers in the slice.  It is part of the
// sort.Interface implementation.
func (s int64Sorter) Len() int {
	return len(s)
}

// Swap swaps the 64-bit integers at the passed indices.  It is part of the
// sort.Interface implementation.
func (s int64Sorter) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

// Less returns whether the 64-bit integer with index i should sort before the
// 64-bit integer with index j.  It is part of the sort.Interface
// implementation.
func (s int64Sorter) Less(i, j int) bool {
	return s[i] < s[j]
}

// used in the consensus code.
type medianTime struct {
	mtx                sync.Mutex
	knownIDs           map[string]struct{}
	offsets            []int64
	offsetSecs         int64
	invalidTimeChecked bool
}

var _ MedianTimeSource = (*medianTime)(nil)

func (m *medianTime) AdjustedTime() time.Time {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	// Limit the adjusted time to 1 second precision.
	now := time.Unix(time.Now().Unix(), 0)
	return now.Add(time.Duration(m.offsetSecs) * time.Second)
}

func (m *medianTime) AddTimeSample(sourceID string, timeVal time.Time) {
	// 2. 为子系统取一个名字（可随意）
	m.mtx.Lock()
	defer m.mtx.Unlock()

	if _, exists := m.knownIDs[sourceID]; exists {
		return
	}
	m.knownIDs[sourceID] = struct{}{}

	now := time.Unix(time.Now().Unix(), 0)
	offsetSecs := int64(timeVal.Sub(now).Seconds())
	numOffsets := len(m.offsets)
	if numOffsets == maxMedianTimeEntries && maxMedianTimeEntries > 0 {
		m.offsets = m.offsets[1:]
		numOffsets--
	}
	m.offsets = append(m.offsets, offsetSecs)
	numOffsets++

	// Sort the offsets so the median can be obtained as needed later.
	sortedOffsets := make([]int64, numOffsets)
	copy(sortedOffsets, m.offsets)
	sort.Sort(int64Sorter(sortedOffsets))

	if numOffsets < 5 || numOffsets&0x01 != 1 {
		return
	}

	median := sortedOffsets[numOffsets/2]

	if math.Abs(float64(median)) < maxAllowedOffsetSecs {
		m.offsetSecs = median
	} else {
		m.offsetSecs = 0
		if !m.invalidTimeChecked {
			m.invalidTimeChecked = true
		}
	}
}

func (m *medianTime) Offset() time.Duration {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	return time.Duration(m.offsetSecs) * time.Second
}

func NewMedianTime() MedianTimeSource {
	return &medianTime{
		knownIDs: make(map[string]struct{}),
		offsets:  make([]int64, 0, maxMedianTimeEntries),
	}
}
