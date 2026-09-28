# Build helpers for the escalator toolkit.

BINARY := escalator

.PHONY: all build static clean vet run-enum run-discover

all: build

# Dynamically-linked build for the machine you are on.
build:
	go build -o $(BINARY) .

# Static build (CGO disabled). Handy for dropping the tool onto the target VM,
# which is an old Ubuntu 16.04 box - a static binary runs regardless of the
# target's glibc version.
static:
	CGO_ENABLED=0 go build -ldflags='-s -w' -o $(BINARY) .

vet:
	go vet ./...

clean:
	rm -f $(BINARY)

run-discover: build
	./$(BINARY) discover

run-enum: build
	./$(BINARY) enum
