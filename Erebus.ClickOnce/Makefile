CONFIG ?= Release
PROJECT := Erebus.ClickOnce.csproj
PUBPROFILE := Properties/PublishProfiles/ClickOnce.pubxml
TFM := net8.0-windows
RID ?= win-x64

.PHONY: publish clean

publish:
	dotnet publish $(PROJECT) \
		/p:PublishProfile=$(PUBPROFILE) \
		/p:Configuration=$(CONFIG) \
		/p:TargetFramework=$(TFM) \
		/p:RuntimeIdentifier=$(RID)

clean:
	rm -rf bin obj
