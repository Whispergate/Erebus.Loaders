PROJECT := Erebus.ClickOnce.csproj
PUBPROFILE := Properties/PublishProfiles/ClickOnce.pubxml
TFM := net7.0-windows
RID ?= win-x64

.PHONY: debug release publish clean

debug:
	dotnet publish $(PROJECT) \
		/p:PublishProfile=$(PUBPROFILE) \
		/p:Configuration=Debug \
		/p:TargetFramework=$(TFM) \
		/p:RuntimeIdentifier=$(RID)

release:
	dotnet publish $(PROJECT) \
		/p:PublishProfile=$(PUBPROFILE) \
		/p:Configuration=Release \
		/p:TargetFramework=$(TFM) \
		/p:RuntimeIdentifier=$(RID)

publish: release

clean:
	rm -rf bin obj
