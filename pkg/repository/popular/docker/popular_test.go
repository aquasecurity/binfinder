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
		enableAllTags    bool
	}{
		{
			name: "happy path",
			apiResponse: `{
  "Next": "",
  "Results": [
    {
      "Name": "foo1"
    }, 
    {
      "Name": "foo2"
    }
  ]
}`,
			tagAPIResponse: `{
  "Results": [
    {
      "Name": "tag1"
    },
    {
      "Name": ""
    },
    {
      "Name": "tag2"
    }
  ]
}
`,
			expectedResponse: []string{"foo1:tag1", "foo2:tag1"},
		},
		{
			name: "happy path - with enabledAllTags true",
			apiResponse: `{
  "Next": "",
  "Results": [
    {
      "Name": "foo1"
    }, 
    {
      "Name": "foo2"
    }
  ]
}`,
			tagAPIResponse: `{
  "Results": [
    {
      "Name": "tag1"
    },
    {
      "Name": ""
    },
    {
      "Name": "tag2"
    }
  ]
}
`,
			enableAllTags:    true,
			expectedResponse: []string{"foo1:tag1", "foo1:", "foo1:tag2", "foo2:tag1", "foo2:"},
		},
		{
			name:        "sad path, invalid apiResponse JSON",
			apiResponse: `invalidjson`,
			expectedErr: "invalid character 'i' looking for beginning of value",
		},
		{
			name: "sad path, invalid tagAPIResponse JSON",
			apiResponse: `{
  "Next": "",
  "Results": [
    {
      "Name": "foo1"
    }, 
    {
      "Name": "foo2"
    }
  ]
}`,
			tagAPIResponse:   `invalidjson`,
			expectedResponse: []string(nil),
		},
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

			p := NewPopularProviderWithConfig(1*time.Second, tsAPI.URL, tsTagAPI.URL+`/%s`)
			got, err := p.GetPopularImages(context.Background(), 5, tc.enableAllTags)
			switch {
			case tc.expectedErr != "":
				assert.Equal(t, tc.expectedErr, err.Error(), tc.name)
			default:
				assert.NoError(t, err, tc.name)
			}
			assert.Equal(t, tc.expectedResponse, got, tc.name)
		})
	}
}
