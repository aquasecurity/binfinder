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
		expectedErr      string
		expectedResponse []string
	}{
		{
			name:             "happy path",
			apiResponse:      `{"Repositories":[{"Namespace":"foons1","Name":"foo1"},{"Namespace":"foons2","Name":"foo2"}, {"Namespace":"foons3","Name":"foo3"}]}`,
			tagAPIResponse:   `[{"Name":"oldtag","UpdatedAt":"2020-09-04T19:14:03-07:00"},{"Name":"newtag","UpdatedAt":"2020-09-04T19:25:06-07:00"}]`,
			expectedResponse: []string{"foons1/foo1:newtag", "foons2/foo2:newtag"},
		},
		{
			name:        "sad path, invalid apiResponse JSON",
			apiResponse: `invalidjson`,
			expectedErr: "invalid character 'i' looking for beginning of value",
		},
		{
			name:             "sad path, invalid tagAPIResponse JSON",
			apiResponse:      `{"Repositories":[{"Namespace":"foons1","Name":"foo1"},{"Namespace":"foons2","Name":"foo2"}]}`,
			tagAPIResponse:   `invalidjson`,
			expectedResponse: []string{},
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
				case strings.Contains(r.URL.String(), getAllRepos):
					_, _ = fmt.Fprint(w, tc.apiResponse)
					return
				}
			}))
			defer tsAPI.Close()

			p := NewPopularProvider(tsAPI.URL, "foouser", "foopassword")
			got, err := p.GetPopularImages(context.Background(), 2)
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
