package blockchain

type timeSorter []int64

func (s timeSorter) Len() int {
	return len(s)
}

func (s timeSorter) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (s timeSorter) Less(i, j int) bool {
	return s[i] < s[j]
}
