package main

import (
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