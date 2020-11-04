package model

type DockerResp struct {
	Next    string
	Results []struct {
		Name string
	}
}
