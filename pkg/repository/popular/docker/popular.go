package docker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/aquasecurity/binfinder/pkg/model"
	"github.com/aquasecurity/binfinder/pkg/repository/popular"
)

const (
	dockerAPI    = "https://hub.docker.com/api/content/v1/products/search?image_filter=official&page=%v&page_size=100&q=&type=image"
	dockerTagAPI = "https://hub.docker.com/v2/repositories/library/%v/tags?page=1&page_size=1"
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
			tag, err := p.getImageTags(img.Slug)
			if err != nil {
				log.Printf("error fetching the tag for image: %v %s", img, err.Error())
				continue
			}
			result = append(result, img.Slug+":"+tag)
			if len(result) == top {
				return result, nil
			}
		}
		page++
	}
}

func (p *Provider) getImageTags(img string) (string, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf(dockerTagAPI, img), nil)
	if err != nil {
		return "", err
	}
	req.Header.Add("Accept", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	type response struct {
		Results []struct {
			Name string
		}
	}
	image := response{}
	if err = json.NewDecoder(resp.Body).Decode(&image); err != nil {
		return "", err
	}
	if len(image.Results) < 1 {
		return "", errors.New("invalid tag response")
	}
	return image.Results[0].Name, nil
}
