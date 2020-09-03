package main

import (
	"errors"
	"io/ioutil"
	"os"
	"testing"

	dockerClient "github.com/docker/docker/client"

	"github.com/docker/docker/api/types"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/golang/mock/gomock"

	"github.com/aquasecurity/binfinder/pkg/contract"
)

func TestGetOS(t *testing.T) {
	testCases := []struct {
		name            string
		inputImageName  string
		outputImageName string
		expectedErr     error
	}{
		{
			name:            "alpine",
			inputImageName:  "alpine:3.10",
			outputImageName: `NAME="Alpine Linux"`,
		},
		{
			name:            "ubuntu",
			inputImageName:  "ubuntu:xenial",
			outputImageName: `NAME="Ubuntu"`,
		},
		{
			name:            "centos",
			inputImageName:  "centos:6",
			outputImageName: `CentOS release 6.10 (Final)`,
		},
		{
			name:            "centos",
			inputImageName:  "centos:7",
			outputImageName: `NAME="CentOS Linux"`,
		},
	}

	for _, tc := range testCases {
		os, err := getOS(tc.inputImageName)
		assert.Equal(t, tc.expectedErr, err, tc.name)
		assert.Equal(t, tc.outputImageName, os, tc.name)
	}
}

func TestPullImage(t *testing.T) {
	testcases := []struct {
		name        string
		username    string
		password    string
		expectedErr error
	}{
		{
			name: "happy path, no username and pass",
		},
		{ // FIXME: This case fails, it should pass.
			name:     "happy path, username and password set",
			username: "rahul23",
			password: "Rahul@kiet1",
		},
		{ // FIXME: This should return a meaningful error that tells that password is not set.
			name:        "sad path, only username set",
			username:    "foouser",
			expectedErr: errors.New("alpine:3.10: pull image expects valid password for user"),
		},
	}

	for _, tc := range testcases {
		if tc.username != "" {
			user = &tc.username
		}

		if tc.password != "" {
			password = &tc.password
		}
		var err error
		cli, err = dockerClient.NewEnvClient()
		require.Nil(t, err)
		err = pullImage("alpine:3.10")
		assert.Equal(t, tc.expectedErr, err, tc.name)
	}
}

func TestExportAnalysis(t *testing.T) {
	testcases := []struct {
		name           string
		goldenDir      string
		expectedOutput string
		expectedErr    error
	}{
		{
			name:      "happy path, good data only",
			goldenDir: "goldens/good-data",
			expectedOutput: `/usr/bin/grep,1
/usr/bin/rpm,1
/usr/bin/sed,1
/usr/sbin/chkconfig,1
/usr/sbin/install-info,1
/usr/sbin/ldconfig,1
`,
		},
		{
			name:      "happy path, good and bad data",
			goldenDir: "goldens/good-and-bad-data",
			expectedOutput: `/usr/bin/grep,1
/usr/bin/rpm,1
/usr/bin/sed,2
/usr/sbin/chkconfig,1
/usr/sbin/install-info,1
/usr/sbin/ldconfig,1
`,
		},
		{
			name:      "happy path, empty valid dir with no files",
			goldenDir: "goldens/empty-data",
		},
		{
			name:      "sad path, invalid data dir",
			goldenDir: "foobarbaz",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			outputDir = &tc.goldenDir
			d, _ := ioutil.TempFile("", "TestExportAnalysis-*")
			defer func() {
				os.RemoveAll(d.Name())
			}()
			exportAnalysis(d.Name())
			b, err := ioutil.ReadFile(d.Name())
			assert.Equal(t, tc.expectedErr, err, tc.name)
			assert.Equal(t, tc.expectedOutput, string(b), tc.name)
		})
	}
}

func Test_isDockerDaemonRunning(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	m := contract.NewMockDockerContract(ctrl)
	testCases := []struct {
		name     string
		f        func()
		expected bool
	}{
		{
			name:     "docker daemon running",
			expected: true,
			f: func() {
				m.EXPECT().Info(gomock.Any()).Return(types.Info{}, nil)
			},
		},
		{
			name:     "docker daemon not-running",
			expected: false,
			f: func() {
				m.EXPECT().Info(gomock.Any()).Return(types.Info{}, errors.New("Error response from daemon: dial unix docker.raw.sock: connect: connection refused"))
			},
		},
	}
	for _, tc := range testCases {
		cli = m
		tc.f()
		got := isDockerDaemonRunning()
		require.Equal(t, got, tc.expected, "want %v, got %v", tc.expected, got)
	}
}
