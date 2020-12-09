.PHONY: run
run:
	go build -o binfinder
	echo "running binfinder on 163 images"
	./binfinder --top=163
	echo "running analysis on resulting jsons"
	./binfinder --analyze
	echo "done...check analysis.json"

build:
	go build -o binfinder

clean:
	rm -f ./binfinder

test:
	go test -v ./...