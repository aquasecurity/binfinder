package popular

import "context"

type ImageProvider interface {
	GetPopularImages(ctx context.Context, top int, enableAllTags bool) ([]string, error)
}
