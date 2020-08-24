package popular

import "context"

type ImageProvider interface {
	GetPopularImages(ctx context.Context, top int) ([]string, error)
}
