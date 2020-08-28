package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/aquasecurity/binfinder/pkg/model"
	"github.com/aquasecurity/binfinder/pkg/repository/popular"
)

const (
	dockerAPI = "https://hub.docker.com/api/content/v1/products/search?image_filter=official&page=%v&page_size=100&q=&type=image"
)

type Provider struct {
	client *http.Client
}

func NewPopularProvider() popular.ImageProvider {
	return &Provider{client: &http.Client{Timeout: 10 * time.Second}}
}

func (p *Provider) GetPopularImages(ctx context.Context, top int) ([]string, error) {
	page := 1
	var result []string
	for {
		req, err := http.NewRequest("GET", fmt.Sprintf(dockerAPI, page), nil)
		if err != nil {
			return nil, err
		}
		req.Header.Add("Accept", "application/json")
		req.Header.Add("Search-Version", "v3")
		resp, err := p.client.Do(req)
		if err != nil {
			return nil, err
		}
		var images model.DockerResp

		if err = json.NewDecoder(resp.Body).Decode(&images); err != nil {
			return nil, err
		}
		for _, img := range images.Summaries {
			result = append(result, img.Slug)
			if len(result) == top {
				return result, nil
			}
		}
		page++
	}
}
