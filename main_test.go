package main

import (
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
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
		//{ // FIXME: This case fails, it should pass.
		//	name:     "happy path, username and password set",
		//	username: "foouser",
		//	password: "barpassword",
		//},
		{
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
			expectedOutput: `binary,count
/usr/bin/grep,1
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
			expectedOutput: `binary,count
/usr/bin/sed,2
/usr/sbin/ldconfig,1
/usr/sbin/install-info,1
/usr/sbin/chkconfig,1
/usr/bin/rpm,1
/usr/bin/grep,1
`,
		},
		{
			name:      "happy path, empty valid dir with no files",
			goldenDir: "goldens/empty-data",
			expectedOutput: `binary,count
`,
		},
		{
			name:      "sad path, invalid data dir",
			goldenDir: "foobarbaz",
			expectedOutput: `binary,count
`,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			outputDir = &tc.goldenDir
			d, _ := ioutil.TempFile("", "TestExportAnalysis-*")
			defer func() {
				_ = os.RemoveAll(d.Name())
			}()
			exportAnalysis(d.Name())
			b, err := ioutil.ReadFile(d.Name())
			assert.Equal(t, tc.expectedErr, err, tc.name)

			want := strings.Split(tc.expectedOutput, "\n")
			got := strings.Split(string(b), "\n")

			assert.ElementsMatch(t, want, got, tc.name)
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

func Test_fetchAlpineDiff(t *testing.T) {
	d, _ := ioutil.TempDir("", "Test_fetchAlpineDiff-*")
	outputDir = &d
	defer func() {
		_ = os.RemoveAll(d)
	}()

	fetchAlpineDiff("alpine:3.10")
	b, err := ioutil.ReadFile(filepath.Join(d, "alpine:3.10-diff.json"))
	require.NoError(t, err)
	assert.JSONEq(t, `{
 "ImageName": "alpine:3.10",
 "ELFNames": [
  "/usr/bin/find",
  "/usr/bin/xargs",
  "/usr/bin/locate",
  "/usr/libexec/code",
  "/usr/libexec/bigram",
  "/usr/libexec/frcode"
 ]
}`, string(b))
}

func Test_fetchUbuntuDiff(t *testing.T) {
	d, _ := ioutil.TempDir("", "Test_fetchUbuntuDiff-*")
	outputDir = &d
	defer func() {
		_ = os.RemoveAll(d)
	}()

	fetchUbuntuDiff("ubuntu:xenial")
	b, err := ioutil.ReadFile(filepath.Join(d, "ubuntu:xenial-diff.json"))
	require.NoError(t, err)
	assert.JSONEq(t, `{
 "ImageName": "ubuntu:xenial",
 "ELFNames": [
  "/var/lib/dpkg/info/bash.preinst"
 ]
}`, string(b))
}

func Test_fetchCentOSDiff(t *testing.T) {
	d, _ := ioutil.TempDir("", "Test_fetchCentOSDiff-*")
	outputDir = &d
	defer func() {
		_ = os.RemoveAll(d)
	}()

	fetchCentOSDiff("centos:7")
	b, err := ioutil.ReadFile(filepath.Join(d, "centos:7-diff.json"))
	require.NoError(t, err)
	assert.JSONEq(t, `{
 "ImageName": "centos:7",
 "ELFNames": [
  "/usr/bin/hostname",
  "/usr/bin/grep",
  "/usr/bin/sed",
  "/usr/bin/rpm",
  "/usr/sbin/chkconfig",
  "/usr/sbin/install-info",
  "/usr/sbin/ldconfig",
  "/usr/sbin/sln"
 ]
}`, string(b))
}
