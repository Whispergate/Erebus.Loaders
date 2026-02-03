PROJECT := Erebus.ClickOnce.csproj
TFM := net7.0-windows
RID ?= win-x64
CONFIG ?= Release
PUBLISH_DIR := bin/$(CONFIG)/$(TFM)/$(RID)/publish

# Detect OS for cross-platform cleanup
ifeq ($(OS),Windows_NT)
    CLEANUP_CMD := powershell -ExecutionPolicy Bypass -File cleanup-payload.ps1 -PublishDir "$(PUBLISH_DIR)"
else
    CLEANUP_CMD := bash cleanup-payload.sh "$(PUBLISH_DIR)"
endif

.PHONY: publish debug release clean all cleanup

all: release

publish: release cleanup

debug:
	dotnet publish $(PROJECT) -p:Configuration=Debug -p:TargetFramework=$(TFM) -p:RuntimeIdentifier=$(RID)

release:
	dotnet publish $(PROJECT) -p:Configuration=$(CONFIG) -p:TargetFramework=$(TFM) -p:RuntimeIdentifier=$(RID) -p:PublishSingleFile=true -p:SelfContained=true -p:PublishTrimmed=true -p:DebugType=none -p:DebugSymbols=false

cleanup:
	@echo "[*] Running payload cleanup..."
	@$(CLEANUP_CMD)

clean:
	rm -rf bin obj
