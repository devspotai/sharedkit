package util

// Difference returns elements in x that are not in y.
func Difference[T comparable](x, y []T) []T {
	// Build a set from y for O(1) lookups
	yset := make(map[T]struct{}, len(y))
	for _, v := range y {
		yset[v] = struct{}{}
	}

	// Collect items from x that are not in y
	var diff []T
	for _, v := range x {
		if _, found := yset[v]; !found {
			diff = append(diff, v)
		}
	}
	return diff
}

func Contains[T comparable](slice []T, v T) bool {
	for _, x := range slice {
		if x == v {
			return true
		}
	}
	return false
}
