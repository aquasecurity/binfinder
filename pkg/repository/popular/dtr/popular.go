package dtr

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
	getALlRepo = "/api/v0/repositories"
	getAllTags = "api/v0/repositories/%v/%v/tags"
)

var (
	replacer = strings.NewReplacer("https://", "", "http://", "")
)

type Provider struct {
	host     string
	user     string
	password string
	client   *http.Client
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
	req, err := http.NewRequest("GET", p.host+getALlRepo, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%v:%v", p.user, p.password))))
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	type response struct {
		Repositories []struct {
			Namespace string
			Name      string
		}
	}
	image := response{}
	if err = json.NewDecoder(resp.Body).Decode(&image); err != nil {
		return nil, err
	}
	var topImages []string
	for _, img := range image.Repositories {
		if len(topImages) == top {
			return topImages, nil
		}
		tag, err := p.getImageTags(img.Namespace, img.Name)
		if err != nil {
			log.Printf("error fetching the tag for image: %v %w", img, err)
		}
		topImages = append(topImages, fmt.Sprintf("%v/%v/%v:%v", replacer.Replace(p.host), img.Namespace, img.Name, tag))
	}
	return topImages, nil
}

func (p *Provider) getImageTags(namespace, img string) (string, error) {
	req, err := http.NewRequest("GET", p.host+fmt.Sprintf(getAllTags, namespace, img), nil)
	if err != nil {
		return "latest", err
	}
	req.Header.Add("Accept", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return "latest", err
	}
	type response struct {
		Name      string
		UpdatedAt string
	}
	tags := []response{}
	if err = json.NewDecoder(resp.Body).Decode(&tags); err != nil {
		return "latest", err
	}
	latestTag := "latest"
	maxUpdateTime := time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, t := range tags {
		updateAt, _ := time.Parse(time.RFC3339, t.UpdatedAt)
		if updateAt.After(maxUpdateTime) {
			maxUpdateTime = updateAt
			latestTag = t.Name
		}
	}
	return latestTag, nil
}
