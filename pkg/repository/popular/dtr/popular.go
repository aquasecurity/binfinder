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
	getAllRepos = "/api/v0/repositories"
	getAllTags  = "/api/v0/repositories/%v/%v/tags"
)

var (
	replacer = strings.NewReplacer("https://", "", "http://", "")
)

type Response struct {
	Repositories []struct {
		Namespace string
		Name      string
	}
}

type TagResponse struct {
	Name      string
	UpdatedAt string
}

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

func (p *Provider) GetPopularImages(ctx context.Context, top int, enableAllTags bool) ([]string, error) {
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

	log.Println("found repos: ", len(image.Repositories))
	var topImages []string
	for _, img := range image.Repositories {
		tags, err := p.getImageTags(img.Namespace, img.Name, enableAllTags)
		if err != nil {
			log.Printf("error fetching the tag for image: %v %s", img, err.Error())
		}
		if tags == nil {
			log.Printf("no valid tag found for image: %v/%v\n", img.Namespace, img.Name)
			continue
		}
		for _, tag := range tags {
			topImages = append(topImages, fmt.Sprintf("%v/%v/%v:%v", replacer.Replace(p.host), img.Namespace, img.Name, tag))
			if len(topImages) == top {
				return topImages, nil
			}
		}
	}
	log.Println("num of top images found: ", len(topImages))
	return topImages, nil
}

func (p *Provider) getImageTags(namespace, img string, enableAllTags bool) ([]string, error) {
	req, err := http.NewRequest("GET", p.host+fmt.Sprintf(getAllTags, namespace, img), nil)
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

	var tags []TagResponse
	if err = json.NewDecoder(resp.Body).Decode(&tags); err != nil {
		return nil, err
	}
	log.Println("found tags: ", len(tags), " for image: ", img)
	var imageTags []string
	latestTag := ""
	maxUpdateTime := time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, t := range tags {
		imageTags = append(imageTags, t.Name)
		updateAt, _ := time.Parse(time.RFC3339, t.UpdatedAt)
		if updateAt.After(maxUpdateTime) {
			maxUpdateTime = updateAt
			latestTag = t.Name
		}

	}
	if enableAllTags {
		return imageTags, nil
	}
	log.Println("latest tag: ", latestTag, "for image: ", img)
	return []string{latestTag}, nil
}
