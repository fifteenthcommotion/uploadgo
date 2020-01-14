upload-go: upload.go
	go build -o upload-go upload.go

.PHONY: clean
.PHONY: install
.PHONY: build

clean:
	rm upload-go

install:
	install -m 0555 upload-go /usr/local/bin

build: upload-go
