package main

import (
	"errors"
	"testing"

	"github.com/docker/docker/api/types"

	"github.com/stretchr/testify/require"

	"github.com/golang/mock/gomock"

	"github.com/aquasecurity/binfinder/pkg/contract"
)

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
