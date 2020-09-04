package docker

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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
			apiResponse:      `{"Summaries":[{"Name":"foo1","Slug":"slug1"},{"Name":"foo2","Slug":"slug2"}]}`,
			tagAPIResponse:   `{"Results":[{"Name":"tag1"},{"Name":""},{"Name":"tag2"}]}`,
			expectedResponse: []string{"slug1:tag1", "slug2:tag1", "slug1:tag1", "slug2:tag1", "slug1:tag1"},
		},
		{
			name:        "sad path, invalid apiResponse JSON",
			apiResponse: `invalidjson`,
			expectedErr: "invalid character 'i' looking for beginning of value",
		},
		//{ // FIXME: This goes into an infinite loop
		//	name:           "sad path, invalid tagAPIResponse JSON",
		//	apiResponse:    `{"Summaries":[{"Name":"foo1","Slug":"slug1"},{"Name":"foo2","Slug":"slug2"}]}`,
		//	tagAPIResponse: `invalidjson`,
		//	expectedErr:    "foo",
		//},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tsAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = fmt.Fprint(w, tc.apiResponse)
			}))
			defer tsAPI.Close()

			tsTagAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = fmt.Fprint(w, tc.tagAPIResponse)
			}))
			defer tsTagAPI.Close()

			p := NewPopularProviderWithConfig(1*time.Second, tsAPI.URL+`/%d`, tsTagAPI.URL+`/%s`)
			got, err := p.GetPopularImages(context.Background(), 5)
			switch {
			case tc.expectedErr != "":
				assert.Equal(t, tc.expectedErr, err.Error(), tc.name)
			default:
				assert.NoError(t, err, tc.name)
			}
			assert.ElementsMatch(t, tc.expectedResponse, got, tc.name)
		})
	}
}
