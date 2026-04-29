ARCH ?= x64

.PHONY: all deps package clean release publish

all: release

# Skip npm ci when node_modules is already populated (e.g. prewarmed
# by the Docker image build). Electron-builder needs the lockfile-pinned
# tree, so we still run npm ci as a fallback when the prewarm is missing.
deps:
	@if [ -d node_modules ] && [ -e node_modules/.package-lock.json ]; then \
		echo "[deps] node_modules already present, skipping npm ci"; \
	else \
		npm ci --no-audit --no-fund --prefer-offline --loglevel=error 2>/dev/null \
			|| npm install --no-audit --no-fund --prefer-offline --loglevel=error; \
	fi

package:
	npx --no-install electron-builder --win nsis --$(ARCH) --publish never

release: deps package

publish: release

clean:
	rm -rf dist build/resources node_modules
