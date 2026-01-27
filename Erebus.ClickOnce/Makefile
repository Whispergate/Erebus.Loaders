PROJECT := Erebus.ClickOnce.csproj
PUBPROFILE := Properties/PublishProfiles/ClickOnce.pubxml
TFM := net7.0-windows
RID ?= win-x64
CONFIG ?= Release

.PHONY: publish debug release clean all

all: debug release

publish: release

debug:
	dotnet publish $(PROJECT) \
		/p:PublishProfile=$(PUBPROFILE) \
		/p:Configuration=Debug \
		/p:TargetFramework=$(TFM) \
		/p:RuntimeIdentifier=$(RID)

release:
	dotnet publish $(PROJECT) \
		/p:PublishProfile=$(PUBPROFILE) \
		/p:Configuration=$(CONFIG) \
		/p:TargetFramework=$(TFM) \
		/p:RuntimeIdentifier=$(RID)

clean:
	rm -rf bin obj
