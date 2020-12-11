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
		expectedNumImages   int
		enableAllTags       bool
	}{
		{
			name:                "happy path",
			apiResponse:         `{"Repositories":["foo1", "foo2", "foo3", "foo4", "foo5", "foo6"]}`,
			tagAPIResponseValid: true,
			expectedNumImages:   4,
			expectedResponse:    []string{"foo1:newtag1", "foo2:newtag2", "foo3:newtag3", "foo4:newtag4"},
		},
		{
			name:                "happy path - with enableAllTags true",
			apiResponse:         `{"Repositories":["foo1", "foo2", "foo3", "foo4", "foo5", "foo6"]}`,
			tagAPIResponseValid: true,
			expectedNumImages:   4,
			expectedResponse:    []string{"foo1:newtag1", "foo1:oldtag1", "foo2:newtag2", "foo3:newtag3"},
			enableAllTags:       true,
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
					_, _ = fmt.Fprint(w, `{"Tags":["newtag1", "oldtag1"]}`)
					return
				case strings.Contains(r.URL.String(), fmt.Sprintf(getAllTags, "foo2")):
					_, _ = fmt.Fprint(w, `{"Tags":["newtag2"]}`)

					return
				case strings.Contains(r.URL.String(), fmt.Sprintf(getAllTags, "foo3")):
					_, _ = fmt.Fprint(w, `{"Tags":["newtag3", "oldtag3"]}`)
					return
				case strings.Contains(r.URL.String(), fmt.Sprintf(getAllTags, "foo4")):
					_, _ = fmt.Fprint(w, `{"Tags":["newtag4"]}`)
					return
					//foo5 is intentionally missing
				case strings.Contains(r.URL.String(), fmt.Sprintf(getAllTags, "foo6")):
					_, _ = fmt.Fprint(w, `{"Tags":["newtag6", "oldtag6"]}`)
					return
				case strings.Contains(r.URL.String(), getAllRepos):
					_, _ = fmt.Fprint(w, tc.apiResponse)
					return
				}
			}))
			defer tsAPI.Close()

			p := NewPopularProvider(tsAPI.URL, "foouser", "foopassword")
			got, err := p.GetPopularImages(context.Background(), tc.expectedNumImages, tc.enableAllTags)
			fmt.Println(got)
			switch {
			case tc.expectedErr != "":
				assert.Equal(t, tc.expectedErr, err.Error(), tc.name)
			default:
				assert.NoError(t, err, tc.name)
			}
			re := regexp.MustCompile(`127.0.0.1:\d*/`)

			assert.Equal(t, tc.expectedNumImages, len(got), tc.name)
			for _, g := range got {
				s := re.Split(g, -1)[1]
				assert.Contains(t, tc.expectedResponse, s)
			}
		})
	}
}
