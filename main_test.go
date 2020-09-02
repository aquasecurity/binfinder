package main

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGetOS(t *testing.T) {
	testCases := []struct {
		name string
		inputImageName string
		outputImageName string
		expectedErr error
	}{
		{
			name: "alpine",
			inputImageName: "alpine:3.10",
			outputImageName: `NAME="Alpine Linux"`,
		},
		{
			name: "ubuntu",
			inputImageName: "ubuntu:xenial",
			outputImageName: `NAME="Ubuntu"`,
		},
		{
			name: "centos",
			inputImageName: "centos:6",
			outputImageName: `CentOS release 6.10 (Final)`,
		},
		{
			name: "centos",
			inputImageName: "centos:7",
			outputImageName: `NAME="CentOS Linux"`,
		},
	}

	for _, tc := range testCases{
		os, err := getOS(tc.inputImageName)
		assert.Equal(t, tc.expectedErr, err, tc.name)
		assert.Equal(t, tc.outputImageName, os, tc.name)
	}
}

func TestPullImage(t *testing.T){
	testcases := []struct{
		name string
		username string
		password string
		expectedErr error
	}{
		{
			name: "happy path, no username and pass",
		},
		{ // FIXME: This case fails, it should pass.
			name: "happy path, username and password set",
			username: "foouser",
			password: "foopass",
		},
		{ // FIXME: This should return a meaningful error that tells that password is not set.
			name: "sad path, only username set",
			username: "foouser",
			expectedErr: errors.New("password not set"),
		},
	}

	for _, tc := range testcases{
		if tc.username != "" {
			user = &tc.username
		}

		if tc.password != "" {
			password = &tc.password
		}

		err := pullImage("alpine:3.10")
		assert.Equal(t, tc.expectedErr, err, tc.name)
	}
}