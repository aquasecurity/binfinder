package contract

import (
	"context"
	"io"

	"github.com/docker/docker/api/types"
)

// DockerContract is the interface of docker client
type DockerContract interface {
	Info(ctx context.Context) (types.Info, error)
	ImagePull(ctx context.Context, ref string, options types.ImagePullOptions) (io.ReadCloser, error)
}
