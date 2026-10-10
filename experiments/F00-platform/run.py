import datetime
import json
from pathlib import Path
import plistlib
import subprocess


def execute(run):
    observations = {}
    commands = {
        'os': ['sw_vers'], 'architecture': ['uname', '-m'],
        'xcode': ['xcodebuild', '-version'], 'sdk': ['xcrun', '--show-sdk-version'],
        'sip': ['csrutil', 'status'], 'enrollment': ['profiles', 'status', '-type', 'enrollment'],
        'extensions': ['systemextensionsctl', 'list'], 'sing_box': ['sing-box', 'version'],
    }
    for name, args in commands.items():
        result = run.command(args)
        observations[name] = {'returncode': result.returncode, 'output': result.stdout.strip()}
    identities = run.command(['security', 'find-identity', '-v', '-p', 'codesigning']).stdout
    observations['identities'] = {kind: identities.count('"' + kind + ':') for kind in ['Apple Development', 'Apple Distribution', 'Developer ID Application', '3rd Party Mac Developer Application']}
    profiles = []
    for root in [Path.home() / 'Library/MobileDevice/Provisioning Profiles', Path.home() / 'Library/Developer/Xcode/UserData/Provisioning Profiles']:
        for path in sorted(list(root.glob('*.provisionprofile')) + list(root.glob('*.mobileprovision'))):
            decoded = subprocess.run(['/usr/bin/security', 'cms', '-D', '-i', str(path)], capture_output=True)
            if decoded.returncode:
                profiles.append({'decoded': False})
                continue
            profile = plistlib.loads(decoded.stdout)
            entitlements = profile.get('Entitlements', {})
            profiles.append({'decoded': True, 'platform': profile.get('Platform'), 'expired': profile['ExpirationDate'] < datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None), 'network_extension': entitlements.get('com.apple.developer.networking.networkextension'), 'system_extension_install': entitlements.get('com.apple.developer.system-extension.install'), 'endpoint_security': entitlements.get('com.apple.developer.endpoint-security.client')})
    observations['profiles'] = profiles
    source = run.root / 'experiments/F00-platform/Sources'
    binary = run.compile_c(source / 'endpoint_security.c', 'endpoint-security', ['-fblocks', '-lEndpointSecurity'])
    # No entitlement is forged, and no ES subscription is installed.
    result = run.command([binary], check=True)
    observations['endpoint_security_runtime'] = [json.loads(line) for line in result.stdout.splitlines()]
    result = run.command(['xcrun', 'swiftc', '-typecheck', source / 'ProviderCompile.swift'], timeout=60)
    observations['provider_typecheck'] = {'returncode': result.returncode, 'stderr': result.stderr}
    run.save('observations.json', observations)
    run.save('cleanup.json', {'persistent_system_changes': False, 'es_clients_deleted_on_success': True, 'extension_installed': False})
    return {'scope': 'F00 local inventory, compile-only NE API check, unentitled ES runtime checks', 'observations': observations, 'conclusion': 'inconclusive for signed provider operation/distribution; inventory is not an activation test'}
