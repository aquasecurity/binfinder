package registryV2

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/aquasecurity/binfinder/pkg/repository/popular"
)

const (
	getAllRepos = "/v2/_catalog"
	getAllTags  = "/v2/%v/tags/list"
)

var (
	replacer = strings.NewReplacer("https://", "", "http://", "")
)

type Response struct {
	Repositories []string
}

type TagResponse struct {
	Tags []string
}

type Provider struct {
	host, user, password string
	client               *http.Client
}

func NewPopularProvider(host, user, password string) popular.ImageProvider {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	return &Provider{
		host:     host,
		user:     user,
		password: password,
		client:   &http.Client{Timeout: 10 * time.Second, Transport: tr}}
}

func (p *Provider) GetPopularImages(ctx context.Context, top int) ([]string, error) {
	req, err := http.NewRequest("GET", p.host+getAllRepos, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%v:%v", p.user, p.password))))
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	image := Response{}
	if err = json.NewDecoder(resp.Body).Decode(&image); err != nil {
		return nil, err
	}
	var topImages []string
	for _, img := range image.Repositories {
		tags, err := p.getImageTags(img)
		if err != nil {
			log.Printf("error fetching the tag for image: %v %s", img, err.Error())
		}
		for _, t := range tags {
			if len(topImages) == top {
				return topImages, nil
			}
			topImages = append(topImages, fmt.Sprintf("%v/%v:%v", replacer.Replace(p.host), img, t))
		}
	}
	return topImages, nil
}

func (p *Provider) getImageTags(img string) ([]string, error) {
	req, err := http.NewRequest("GET", p.host+fmt.Sprintf(getAllTags, img), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%v:%v", p.user, p.password))))
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	image := TagResponse{}
	if err = json.NewDecoder(resp.Body).Decode(&image); err != nil {
		return nil, err
	}
	return image.Tags, nil
}
