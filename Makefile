.PHONY: build test vet fmt install clean

build:
	go build -o metsuke .

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

install:
	go install .

clean:
	rm -f metsuke
