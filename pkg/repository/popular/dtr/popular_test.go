package dtr

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestProvider_GetPopularImages(t *testing.T) {
	testCases := []struct {
		name             string
		apiResponse      string
		tagAPIResponse   string
		wantNumTopImages int
		expectedErr      string
		wantImagesList   []string
		enableAllTags    bool
	}{
		{
			name: "happy path",
			apiResponse: `{
	"Repositories": [{
		"Namespace": "foons1",
		"Name": "foo1"
	}, {
		"Namespace": "foons2",
		"Name": "foo2"
	}, {
		"Namespace": "foons3",
		"Name": "foo3"
	}]
}`,
			tagAPIResponse: `[{
	"Name": "oldtag",
	"UpdatedAt": "2020-09-04T19:14:03-07:00"
}, {
	"Name": "newtag",
	"UpdatedAt": "2020-09-04T19:25:06-07:00"
}]`,
			wantNumTopImages: 4,
			wantImagesList:   []string{"foons1/foo1:oldtag", "foons1/foo1:newtag", "foons2/foo2:oldtag", "foons2/foo2:newtag"},
			enableAllTags:    true,
		},
		{
			name: "happy path - only with the latest tag",
			apiResponse: `{
	"Repositories": [{
		"Namespace": "foons1",
		"Name": "foo1"
	}, {
		"Namespace": "foons2",
		"Name": "foo2"
	}, {
		"Namespace": "foons3",
		"Name": "foo3"
	}, {
		"Namespace": "foons4",
		"Name": "foo4"
	}, {
		"Namespace": "foons5",
		"Name": "foo5"
	}]
}`,
			tagAPIResponse: `[{
	"Name": "oldtag",
	"UpdatedAt": "2020-09-04T19:14:03-07:00"
}, {
	"Name": "newtag",
	"UpdatedAt": "2020-09-04T19:25:06-07:00"
}]`,
			wantNumTopImages: 4,
			wantImagesList:   []string{"foons1/foo1:newtag", "foons2/foo2:newtag", "foons3/foo3:newtag", "foons4/foo4:newtag"},
			enableAllTags:    false,
		},
		{
			name:          "sad path, invalid apiResponse JSON",
			apiResponse:   `invalidjson`,
			expectedErr:   "invalid character 'i' looking for beginning of value",
			enableAllTags: true,
		},
		{
			name:           "sad path, invalid tagAPIResponse JSON",
			apiResponse:    `{"Repositories":[{"Namespace":"foons1","Name":"foo1"},{"Namespace":"foons2","Name":"foo2"}]}`,
			tagAPIResponse: `invalidjson`,
			enableAllTags:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tsAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.Contains(r.URL.String(), fmt.Sprintf(getAllTags, "foons1", "foo1")):
					_, _ = fmt.Fprint(w, tc.tagAPIResponse)
					return
				case strings.Contains(r.URL.String(), fmt.Sprintf(getAllTags, "foons2", "foo2")):
					_, _ = fmt.Fprint(w, tc.tagAPIResponse)
					return
				case strings.Contains(r.URL.String(), fmt.Sprintf(getAllTags, "foons3", "foo3")):
					_, _ = fmt.Fprint(w, tc.tagAPIResponse)
					return
				case strings.Contains(r.URL.String(), fmt.Sprintf(getAllTags, "foons4", "foo4")):
					_, _ = fmt.Fprint(w, tc.tagAPIResponse)
					return
				case strings.Contains(r.URL.String(), "/api/v0/repositories?pageSize"):
					assert.Equal(t, fmt.Sprintf("/api/v0/repositories?pageSize=%v", tc.wantNumTopImages), r.URL.String(), tc.name)
					_, _ = fmt.Fprint(w, tc.apiResponse)
					return
				default:
					assert.Fail(t, fmt.Sprintf("invalid path accessed: %s", r.URL.String()), tc.name)
					return
				}
			}))
			defer tsAPI.Close()

			p := NewPopularProvider(tsAPI.URL, "foouser", "foopassword")
			got, err := p.GetPopularImages(context.Background(), tc.wantNumTopImages, tc.enableAllTags)
			switch {
			case tc.expectedErr != "":
				assert.Equal(t, tc.expectedErr, err.Error(), tc.name)
			default:
				assert.NoError(t, err, tc.name)
			}

			var gotImagesList []string
			re := regexp.MustCompile(`127.0.0.1:\d*/`)
			for _, g := range got {
				s := re.Split(g, -1)[1]
				gotImagesList = append(gotImagesList, s)
			}
			assert.Equal(t, tc.wantImagesList, gotImagesList, tc.name)
		})
	}
}
