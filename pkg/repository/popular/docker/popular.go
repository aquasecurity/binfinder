package docker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/aquasecurity/binfinder/pkg/model"
	"github.com/aquasecurity/binfinder/pkg/repository/popular"
)

const (
	dockerAPI    = "https://hub.docker.com/v2/repositories/library/?page=1&page_size=100"
	dockerTagAPI = "https://hub.docker.com/v2/repositories/library/%v/tags"
)

type Response struct {
	Results []struct {
		Name string
	}
}

type Provider struct {
	client    *http.Client
	apiURL    string
	tagAPIURL string
}

func NewPopularProvider() popular.ImageProvider {
	return NewPopularProviderWithConfig(10*time.Second, dockerAPI, dockerTagAPI)
}

func NewPopularProviderWithConfig(timeout time.Duration, apiURL string, tagAPIURL string) popular.ImageProvider {
	return &Provider{
		client:    &http.Client{Timeout: timeout},
		apiURL:    apiURL,
		tagAPIURL: tagAPIURL,
	}
}

func (p *Provider) GetPopularImages(ctx context.Context, top int, enableAllTags bool) ([]string, error) {
	var result []string
	apiURL := p.apiURL
	for {
		log.Println("Fetching page: ", apiURL)
		req, err := http.NewRequest("GET", apiURL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Add("Accept", "application/json")
		req.Header.Add("Search-Version", "v3")
		resp, err := p.client.Do(req)
		defer resp.Body.Close()
		if err != nil {
			log.Println("Fetching page failed: ", err)
			return nil, err
		}
		var images model.DockerResp
		if err = json.NewDecoder(resp.Body).Decode(&images); err != nil {
			return nil, err
		}

		log.Println("Found images: ", len(images.Results))
		for _, img := range images.Results {
			tags, err := p.getImageTags(strings.ToLower(img.Name), enableAllTags)
			if err != nil {
				log.Printf("error fetching the tag for image: %v %s\n", img, err.Error())
				continue
			}
			for _, tag := range tags {
				result = append(result, img.Name+":"+tag)
				if len(result) == top {
					return result, nil
				}
			}
		}
		if images.Next == "" {
			break
		}
		apiURL = images.Next
	}
	return result, nil
}

func (p *Provider) getImageTags(img string, enableAllTags bool) ([]string, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf(p.tagAPIURL, img), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Accept", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	image := Response{}
	if err = json.NewDecoder(resp.Body).Decode(&image); err != nil {
		return nil, err
	}
	if len(image.Results) < 1 {
		return nil, errors.New("invalid tag response")
	}
	var tags []string
	for _, r := range image.Results {
		if !enableAllTags {
			return []string{r.Name}, nil
		}
		tags = append(tags, r.Name)
	}
	return tags, nil
}
