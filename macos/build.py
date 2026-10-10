#!/usr/bin/env python3
"""Generate/build the standalone InVPN app; never installs or activates it."""
import argparse
import plistlib
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parent
REPOSITORY = ROOT.parent


def generate() -> Path:
    objects = {}

    def obj(kind, **values):
        key = f"{len(objects) + 1:024X}"
        objects[key] = dict(isa=kind, **values)
        return key

    def plist(path, value):
        (ROOT / path).write_bytes(plistlib.dumps(value))

    network = {"com.apple.developer.networking.networkextension": ["app-proxy-provider"],
               "com.apple.security.application-groups": ["$(TeamIdentifierPrefix)jp.diverge.invpn"]}
    plist("Host/Host.entitlements", dict(network, **{"com.apple.developer.system-extension.install": True}))
    plist("Provider/Provider.entitlements", dict(network, **{
        "com.apple.security.app-sandbox": True, "com.apple.security.network.client": True,
    }))
    base = {"CFBundleIdentifier": "$(PRODUCT_BUNDLE_IDENTIFIER)",
            "CFBundleExecutable": "$(EXECUTABLE_NAME)", "CFBundleName": "$(PRODUCT_NAME)",
            "CFBundleVersion": "2", "CFBundleShortVersionString": "0.1.0",
            "LSMinimumSystemVersion": "$(MACOSX_DEPLOYMENT_TARGET)"}
    plist("Host/Info.plist", dict(base, CFBundlePackageType="APPL", LSUIElement=True,
        NSSystemExtensionUsageDescription="Route a selected command's TCP flows to one declared IPv4 destination through its VPN."))
    plist("Provider/Info.plist", dict(base, CFBundlePackageType="SYSX",
        NSSystemExtensionUsageDescription="Provide experimental TCP forwarding for one selected process and destination.",
        NetworkExtension={"NEMachServiceName": "$(TeamIdentifierPrefix)$(PRODUCT_BUNDLE_IDENTIFIER)",
                          "NEProviderClasses": {"com.apple.networkextension.app-proxy": "$(PRODUCT_MODULE_NAME).InVPNProvider"}}))

    products = obj("PBXGroup", children=[], name="Products", sourceTree="<group>")
    group = obj("PBXGroup", children=[products], sourceTree="<group>")
    common = {"SDKROOT": "macosx", "MACOSX_DEPLOYMENT_TARGET": "15.0", "SWIFT_VERSION": "5.0",
              "CODE_SIGN_STYLE": "Automatic", "CODE_SIGN_IDENTITY": "Apple Development",
              "ENABLE_HARDENED_RUNTIME": "YES", "CLANG_ENABLE_MODULES": "YES",
              "SWIFT_OPTIMIZATION_LEVEL": "-Onone", "OTHER_LDFLAGS": ["-lproc"]}

    def configs(settings):
        configuration = obj("XCBuildConfiguration", name="Debug", buildSettings=settings)
        return obj("XCConfigurationList", buildConfigurations=[configuration],
                   defaultConfigurationIsVisible=0, defaultConfigurationName="Debug")

    source_references = {}

    def target(name, directory, sources, product_type, extension, bundle):
        files = []
        for path in sources:
            if path not in source_references:
                file_type = "sourcecode.c.c" if path.endswith(".c") else "sourcecode.swift"
                source_references[path] = obj("PBXFileReference", lastKnownFileType=file_type,
                                              path=path, sourceTree="<group>")
                objects[group]["children"].append(source_references[path])
            files.append(obj("PBXBuildFile", fileRef=source_references[path]))
        product_name = bundle if extension == "systemextension" else name
        product = obj("PBXFileReference", explicitFileType="wrapper.application" if extension == "app" else "wrapper.system-extension",
                      path=f"{product_name}.{extension}", sourceTree="BUILT_PRODUCTS_DIR")
        objects[products]["children"].append(product)
        phase = obj("PBXSourcesBuildPhase", buildActionMask=2147483647, files=files,
                    runOnlyForDeploymentPostprocessing=0)
        settings = dict(common, PRODUCT_NAME=product_name, PRODUCT_MODULE_NAME=name,
                        PRODUCT_BUNDLE_IDENTIFIER=bundle, INFOPLIST_FILE=f"{directory}/Info.plist",
                        CODE_SIGN_ENTITLEMENTS=f"{directory}/{directory}.entitlements",
                        SWIFT_OBJC_BRIDGING_HEADER="Shared/ProcessIdentity.h",
                        SKIP_INSTALL="YES" if extension != "app" else "NO", ENABLE_DEBUG_DYLIB="NO")
        native = obj("PBXNativeTarget", name=name, productName=name, productReference=product,
                     productType=product_type, buildConfigurationList=configs(settings),
                     buildPhases=[phase], buildRules=[], dependencies=[])
        return native, product

    shared = ["Shared/Model.swift", "Shared/ProcessIdentity.c"]
    provider, product = target("InVPNProxy", "Provider",
        ["Provider/Provider.swift", "Provider/Relay.swift", "Provider/main.swift"] + shared,
        "com.apple.product-type.system-extension", "systemextension", "jp.diverge.invpn.proxy")
    host, _ = target("InVPN", "Host", ["Host/Host.swift"] + shared,
                     "com.apple.product-type.application", "app", "jp.diverge.invpn")
    embed = obj("PBXBuildFile", fileRef=product, settings={"ATTRIBUTES": ["RemoveHeadersOnCopy"]})
    copy = obj("PBXCopyFilesBuildPhase", buildActionMask=2147483647, files=[embed],
               dstPath="$(CONTENTS_FOLDER_PATH)/Library/SystemExtensions", dstSubfolderSpec=16,
               name="Embed System Extension", runOnlyForDeploymentPostprocessing=0)
    objects[host]["buildPhases"].append(copy)
    objects[host]["dependencies"].append(obj("PBXTargetDependency", target=provider))
    project = obj("PBXProject", attributes={"LastUpgradeCheck": "2700", "TargetAttributes": {
        host: {"SystemCapabilities": {"com.apple.SystemExtension": {"enabled": 1}, "com.apple.NetworkExtensions": {"enabled": 1}}},
        provider: {"SystemCapabilities": {"com.apple.NetworkExtensions": {"enabled": 1}}}}},
        buildConfigurationList=configs(common), compatibilityVersion="Xcode 14.0",
        developmentRegion="en", hasScannedForEncodings=0, knownRegions=["en", "Base"],
        mainGroup=group, productRefGroup=products, projectDirPath="", projectRoot="", targets=[host, provider])
    directory = ROOT / "InVPN.xcodeproj"
    directory.mkdir(exist_ok=True)
    (directory / "project.pbxproj").write_bytes(plistlib.dumps({"archiveVersion": "1", "classes": {},
        "objectVersion": "56", "objects": objects, "rootObject": project}))
    return directory


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--generate-only", action="store_true")
    parser.add_argument("--unsigned", action="store_true", help="Compile without signing/provisioning (cannot activate).")
    parser.add_argument("--team", help="Authorized Apple Developer team ID for a signed development build.")
    parser.add_argument("--derived-data", type=Path, default=REPOSITORY / ".local/build/native")
    arguments = parser.parse_args()
    project = generate()
    if arguments.generate_only:
        print(project)
        return
    if not arguments.unsigned and not arguments.team:
        parser.error("Specify --team for signing, or --unsigned for compilation only.")
    command = ["xcodebuild", "-project", str(project), "-scheme", "InVPN", "-configuration", "Debug",
               "-destination", "platform=macOS,arch=arm64", "-derivedDataPath", str(arguments.derived_data)]
    command += ["CODE_SIGNING_ALLOWED=NO"] if arguments.unsigned else [
        "-allowProvisioningUpdates", f"DEVELOPMENT_TEAM={arguments.team}"]
    subprocess.run(command + ["build"], check=True)


if __name__ == "__main__":
    main()
