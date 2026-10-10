#!/usr/bin/env python3
"""Generate the self-contained, two-target feasibility Xcode project."""
from pathlib import Path
import plistlib

root = Path(__file__).resolve().parent
objects = {}


def obj(kind, **values):
    key = f'{len(objects) + 1:024X}'
    objects[key] = dict(isa=kind, **values)
    return key


def plist(path, value):
    (root / path).write_bytes(plistlib.dumps(value))


# Development signing uses the standard value; Developer ID distribution uses
# the -systemextension variant with separate distribution profiles.
ne = {'com.apple.developer.networking.networkextension': ['app-proxy-provider', 'content-filter-provider'], 'com.apple.security.application-groups': ['$(TeamIdentifierPrefix)jp.diverge.invpn.feasibility']}
plist('Host/Host.entitlements', dict(ne, **{'com.apple.developer.system-extension.install': True}))
plist('Provider/Provider.entitlements', dict(ne, **{'com.apple.security.app-sandbox': True, 'com.apple.security.network.client': True, 'com.apple.security.network.server': True}))
plist('Guard/Guard.entitlements', dict(ne, **{'com.apple.security.app-sandbox': True}))
base = {'CFBundleIdentifier': '$(PRODUCT_BUNDLE_IDENTIFIER)', 'CFBundleExecutable': '$(EXECUTABLE_NAME)', 'CFBundleName': '$(PRODUCT_NAME)', 'CFBundleVersion': '10', 'CFBundleShortVersionString': '0.0.10', 'LSMinimumSystemVersion': '$(MACOSX_DEPLOYMENT_TARGET)'}
plist('Host/Info.plist', dict(base, CFBundlePackageType='APPL', LSUIElement=True, NSSystemExtensionUsageDescription='Run the in-vpn feasibility test for one local receiver port.'))
plist('Provider/Info.plist', dict(base, CFBundlePackageType='SYSX', NSSystemExtensionUsageDescription='Observe and block only the in-vpn test receiver port.', NetworkExtension={'NEMachServiceName': '$(TeamIdentifierPrefix)$(PRODUCT_BUNDLE_IDENTIFIER)', 'NEProviderClasses': {'com.apple.networkextension.app-proxy': '$(PRODUCT_MODULE_NAME).ProbeProvider'}}))
plist('Guard/Info.plist', dict(base, CFBundlePackageType='SYSX', NSSystemExtensionUsageDescription='Test fail-closed filtering for one local receiver port.', NetworkExtension={'NEMachServiceName': '$(TeamIdentifierPrefix)$(PRODUCT_BUNDLE_IDENTIFIER)', 'NEProviderClasses': {'com.apple.networkextension.filter-data': '$(PRODUCT_MODULE_NAME).GuardProvider'}}))
products = obj('PBXGroup', children=[], name='Products', sourceTree='<group>')
group = obj('PBXGroup', children=[products], sourceTree='<group>')
common = {'SDKROOT': 'macosx', 'MACOSX_DEPLOYMENT_TARGET': '15.0', 'SWIFT_VERSION': '5.0', 'CODE_SIGN_STYLE': 'Automatic', 'CODE_SIGN_IDENTITY': 'Apple Development', 'ENABLE_HARDENED_RUNTIME': 'YES', 'CLANG_ENABLE_MODULES': 'YES', 'SWIFT_OPTIMIZATION_LEVEL': '-Onone'}


def configs(settings):
    config = obj('XCBuildConfiguration', name='Debug', buildSettings=settings)
    return obj('XCConfigurationList', buildConfigurations=[config], defaultConfigurationIsVisible=0, defaultConfigurationName='Debug')


def target(name, directory, sources, product_type, extension, bundle):
    files = []
    for path in sources:
        ref = obj('PBXFileReference', lastKnownFileType='sourcecode.swift', path=f'{directory}/{path}', sourceTree='<group>')
        objects[group]['children'].append(ref)
        files.append(obj('PBXBuildFile', fileRef=ref))
    product_name = bundle if extension == 'systemextension' else name
    product = obj('PBXFileReference', explicitFileType='wrapper.application' if extension == 'app' else 'wrapper.system-extension', path=f'{product_name}.{extension}', sourceTree='BUILT_PRODUCTS_DIR')
    objects[products]['children'].append(product)
    phase = obj('PBXSourcesBuildPhase', buildActionMask=2147483647, files=files, runOnlyForDeploymentPostprocessing=0)
    settings = dict(common, PRODUCT_NAME=product_name, PRODUCT_MODULE_NAME=name, PRODUCT_BUNDLE_IDENTIFIER=bundle, INFOPLIST_FILE=f'{directory}/Info.plist', CODE_SIGN_ENTITLEMENTS=f'{directory}/{directory}.entitlements', SKIP_INSTALL='YES' if extension != 'app' else 'NO', ENABLE_DEBUG_DYLIB='NO')
    return obj('PBXNativeTarget', name=name, productName=name, productReference=product, productType=product_type, buildConfigurationList=configs(settings), buildPhases=[phase], buildRules=[], dependencies=[]), product


provider, product = target('InVPNProbe', 'Provider', ['Provider.swift', 'Relay.swift', 'main.swift'], 'com.apple.product-type.system-extension', 'systemextension', 'jp.diverge.invpn.feasibility.proxy')
guard, guard_product = target('InVPNGuard', 'Guard', ['Guard.swift', 'main.swift'], 'com.apple.product-type.system-extension', 'systemextension', 'jp.diverge.invpn.feasibility.guard')
host, _ = target('InVPNFeasibility', 'Host', ['Host.swift'], 'com.apple.product-type.application', 'app', 'jp.diverge.invpn.feasibility')
embed = obj('PBXBuildFile', fileRef=product, settings={'ATTRIBUTES': ['RemoveHeadersOnCopy']})
copy = obj('PBXCopyFilesBuildPhase', buildActionMask=2147483647, files=[embed], dstPath='$(CONTENTS_FOLDER_PATH)/Library/SystemExtensions', dstSubfolderSpec=16, name='Embed System Extension', runOnlyForDeploymentPostprocessing=0)
objects[copy]['files'].append(obj('PBXBuildFile', fileRef=guard_product, settings={'ATTRIBUTES': ['RemoveHeadersOnCopy']}))
objects[host]['buildPhases'].append(copy)
objects[host]['dependencies'].append(obj('PBXTargetDependency', target=guard))
dependency = obj('PBXTargetDependency', target=provider)
objects[host]['dependencies'].append(dependency)
project = obj('PBXProject', attributes={'LastUpgradeCheck': '2700', 'TargetAttributes': {host: {'SystemCapabilities': {'com.apple.SystemExtension': {'enabled': 1}, 'com.apple.NetworkExtensions': {'enabled': 1}}}, provider: {'SystemCapabilities': {'com.apple.NetworkExtensions': {'enabled': 1}}}}}, buildConfigurationList=configs(common), compatibilityVersion='Xcode 14.0', developmentRegion='en', hasScannedForEncodings=0, knownRegions=['en', 'Base'], mainGroup=group, productRefGroup=products, projectDirPath='', projectRoot='', targets=[host, provider, guard])
project_dir = root / 'Feasibility.xcodeproj'
project_dir.mkdir(exist_ok=True)
(project_dir / 'project.pbxproj').write_bytes(plistlib.dumps({'archiveVersion': '1', 'classes': {}, 'objectVersion': '56', 'objects': objects, 'rootObject': project}))
print(project_dir)
