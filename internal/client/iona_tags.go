package client

import "fmt"

// maxTagLen is the maximum length of a client tag.
const maxTagLen = 64

// validateTag returns an error if t can't be used as a client tag.
//
// Iona: tags are free-form instead of being limited to allowedTags, so that
// every filter category can get its own tag for per-device exceptions.  A tag
// still has to be usable in a $ctag rule modifier, and urlfilter only accepts
// lowercase ASCII letters, digits, and underscores there.  allowedTags is kept
// as the list of suggested tags reported by [Storage.AllowedTags].
func validateTag(t string) (err error) {
	if t == "" || len(t) > maxTagLen {
		return fmt.Errorf("invalid tag: %q", t)
	}

	for _, ch := range t {
		if (ch < 'a' || ch > 'z') && (ch < '0' || ch > '9') && ch != '_' {
			return fmt.Errorf("invalid tag: %q", t)
		}
	}

	return nil
}
