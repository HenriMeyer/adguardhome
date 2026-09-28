package client

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateTag(t *testing.T) {
	testCases := []struct {
		name    string
		tag     string
		wantErr bool
	}{{
		name: "known",
		tag:  "device_phone",
	}, {
		name: "free_form",
		tag:  "iona_cat_22",
	}, {
		name: "digits",
		tag:  "cat42",
	}, {
		name: "max_len",
		tag:  strings.Repeat("a", maxTagLen),
	}, {
		name:    "empty",
		tag:     "",
		wantErr: true,
	}, {
		name:    "too_long",
		tag:     strings.Repeat("a", maxTagLen+1),
		wantErr: true,
	}, {
		name:    "uppercase",
		tag:     "Device_phone",
		wantErr: true,
	}, {
		name:    "dash",
		tag:     "iona-cat",
		wantErr: true,
	}, {
		// Would split the tag in a $ctag=a|b rule modifier.
		name:    "pipe",
		tag:     "a|b",
		wantErr: true,
	}, {
		// Would read as a restriction in a $ctag=~tag rule modifier.
		name:    "tilde",
		tag:     "~a",
		wantErr: true,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateTag(tc.tag)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestPersistent_Validate_moreTagsThanKnown(t *testing.T) {
	tags := make([]string, 0, len(allowedTags)+10)
	for i := range cap(tags) {
		tags = append(tags, fmt.Sprintf("iona_cat_%d", i))
	}

	c := &Persistent{
		Name: "many_tags",
		IPs:  []netip.Addr{netip.MustParseAddr("192.0.2.1")},
		UID:  MustNewUID(),
		Tags: tags,
	}

	ctx := testutil.ContextWithTimeout(t, time.Second)
	err := c.validate(ctx, slogutil.NewDiscardLogger(), allowedTags)
	require.NoError(t, err)

	assert.Len(t, c.Tags, len(allowedTags)+10)
}
