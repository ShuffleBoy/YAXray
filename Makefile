.PHONY: app test install clean

app:
	./scripts/build-app.sh

test:
	go test ./...

install: app
	rm -rf /Applications/YAXray.app
	cp -R build/YAXray.app /Applications/

clean:
	rm -rf build
