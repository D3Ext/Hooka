CC = go

all:
	mkdir build/
	export CGO_ENABLED=0
	GOARCH=amd64 GOOS=windows $(CC) build -o build/hooka-amd64-windows.exe main.go

clean:
	rm -rf build/
