package registryV2

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
		name                string
		apiResponse         string
		tagAPIResponseValid bool
		expectedErr         string
		expectedResponse    []string
	}{
		{
			name:                "happy path",
			apiResponse:         `{"Repositories":["foo1", "foo2", "foo3", "foo4", "foo5", "foo6"]}`,
			tagAPIResponseValid: true,
			expectedResponse:    []string{"foo1:tag1", "foo2:tag2", "foo3:tag3", "foo4:tag4"},
		},
		{
			name:        "sad path, invalid apiResponse JSON",
			apiResponse: `invalidjson`,
			expectedErr: "invalid character 'i' looking for beginning of value",
		},
		{
			name:             "sad path, invalid tagAPIResponse JSON",
			apiResponse:      `{"Repositories":["foo1", "foo2", "foo3", "foo4", "foo5", "foo6"]}`,
			expectedResponse: []string{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tsAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !tc.tagAPIResponseValid && strings.Contains(r.URL.String(), "tags/list") {
					_, _ = fmt.Fprint(w, "invalidjson")
					return
				}

				switch {
				case strings.Contains(r.URL.String(), fmt.Sprintf(getAllTags, "foo1")):
					_, _ = fmt.Fprint(w, `{"Tags":["tag1"]}`)
					return
				case strings.Contains(r.URL.String(), fmt.Sprintf(getAllTags, "foo2")):
					_, _ = fmt.Fprint(w, `{"Tags":["tag2"]}`)
					return
				case strings.Contains(r.URL.String(), fmt.Sprintf(getAllTags, "foo3")):
					_, _ = fmt.Fprint(w, `{"Tags":["tag3"]}`)
					return
				case strings.Contains(r.URL.String(), fmt.Sprintf(getAllTags, "foo4")):
					_, _ = fmt.Fprint(w, `{"Tags":["tag4"]}`)
					return
					//foo5 is intentionally missing
				case strings.Contains(r.URL.String(), fmt.Sprintf(getAllTags, "foo6")):
					_, _ = fmt.Fprint(w, `{"Tags":["tag6"]}`)
					return
				case strings.Contains(r.URL.String(), getAllRepos):
					_, _ = fmt.Fprint(w, tc.apiResponse)
					return
				}
			}))
			defer tsAPI.Close()

			p := NewPopularProvider(tsAPI.URL, "foouser", "foopassword")
			got, err := p.GetPopularImages(context.Background(), 4)
			fmt.Println(got)
			switch {
			case tc.expectedErr != "":
				assert.Equal(t, tc.expectedErr, err.Error(), tc.name)
			default:
				assert.NoError(t, err, tc.name)
			}
			re := regexp.MustCompile(`127.0.0.1:\d*/`)
			for _, g := range got {
				s := re.Split(g, -1)[1]
				assert.Contains(t, tc.expectedResponse, s)
			}
		})
	}
}
