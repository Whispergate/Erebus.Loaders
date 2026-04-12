ARCH ?= x64

.PHONY: all deps package clean release publish

all: release

deps:
	npm ci --no-audit --no-fund --loglevel=error 2>/dev/null || npm install --no-audit --no-fund --loglevel=error

package:
	npx --no-install electron-builder --win nsis --$(ARCH) --publish never

release: deps package

publish: release

clean:
	rm -rf dist build/resources node_modules
