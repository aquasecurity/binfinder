package model

type DockerResp struct {
	Summaries []struct {
		Name string
		Slug string
	}
}
