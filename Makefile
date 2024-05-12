TEST?=$$(go list ./... | grep -v 'vendor')
HOSTNAME=local
NAMESPACE=provider
NAME=psm
BINARY=terraform-provider-${NAME}
VERSION=0.1.119
OS_ARCH ?= darwin_arm64 # Default OS_ARCH, can be overridden by an environment variable

# Options: darwin_arm64, linux_amd64, windows_amd64
OS=$(shell echo $(OS_ARCH) | cut -d_ -f1)
ARCH=$(shell echo $(OS_ARCH) | cut -d_ -f2)

default: install

build:
	go build -o ${BINARY}_${OS_ARCH}

release:
	goreleaser release --rm-dist --snapshot --skip-publish --skip-sign

install: build
	mkdir -p ~/.terraform.d/plugins/${HOSTNAME}/${NAMESPACE}/${NAME}/${VERSION}/${OS_ARCH}
	mv ${BINARY}_${OS_ARCH} ~/.terraform.d/plugins/${HOSTNAME}/${NAMESPACE}/${NAME}/${VERSION}/${OS_ARCH}

test: 
	go test -i $(TEST) || exit 1                                                   
	echo $(TEST) | xargs -t -n4 go test $(TESTARGS) -timeout=30s -parallel=4                    

testacc: 
	TF_ACC=1 go test $(TEST) -v $(TESTARGS) -timeout 120m

