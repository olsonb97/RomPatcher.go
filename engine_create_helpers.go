package rompatcher

func repeatedByteRun(data []byte) bool {
	if len(data) <= 2 {
		return false
	}
	for _, value := range data[1:] {
		if value != data[0] {
			return false
		}
	}
	return true
}
