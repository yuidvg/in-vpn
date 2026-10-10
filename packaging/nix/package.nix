{
  lib,
  python3,
  sing-box,
}:

assert lib.assertMsg (lib.hasPrefix "1.14." sing-box.version)
  "InVPN 0.1.0 requires sing-box 1.14.x; qualify a newer backend before updating nixpkgs";

python3.pkgs.buildPythonApplication {
  pname = "invpn";
  version = "0.1.0";
  pyproject = true;

  src = lib.fileset.toSource {
    root = ../..;
    fileset = lib.fileset.unions [
      ../../pyproject.toml
      ../../LICENSE
      (lib.fileset.fileFilter (file: file.hasExt "py") ../../src/invpn)
      (lib.fileset.fileFilter (file: lib.hasPrefix "test_" file.name && file.hasExt "py") ../../tests)
      ../../bin/in-vpn
      ../../scripts/nix-package
    ];
  };

  build-system = [ python3.pkgs.setuptools ];

  # The standard Python wrapper changes PATH and PYTHONNOUSERSITE. InVPN must
  # preserve those for the user's command. -I isolates only this interpreter.
  dontWrapPythonPrograms = true;
  postInstall = ''
        cat > "$out/bin/in-vpn" <<EOF
    #!${python3.interpreter} -I
    import os
    import sys
    sys.path.insert(0, "$out/${python3.sitePackages}")
    os.environ.setdefault("INVPN_SING_BOX", "${sing-box}/bin/sing-box")
    from invpn.cli import main
    raise SystemExit(main())
    EOF
        chmod +x "$out/bin/in-vpn"
        rm "$out/bin/invpn"
        ln -s in-vpn "$out/bin/invpn"
        install -Dm644 LICENSE "$out/share/licenses/invpn/LICENSE"
  '';

  # Pure checks and CLI refusals run inside the derivation. Local socket and
  # WireGuard integration checks run separately, outside the Darwin sandbox.
  checkPhase = ''
    runHook preCheck
    PYTHONPATH=src:tests ${python3.interpreter} -m unittest \
      test_profiles test_backend_selection test_nix_source test_contract \
      test_transport.BackendSettingsTests test_transport.BackendLifecycleTests
    runHook postCheck
  '';
  pythonImportsCheck = [
    "invpn"
    "invpn.cli"
  ];
  doInstallCheck = true;
  postCheck = ''
    test "$($out/bin/in-vpn --version)" = "0.1.0"
    "$out/bin/invpn" capabilities --json > capabilities.json
    ${python3.interpreter} -c 'import json; c = json.load(open("capabilities.json")); assert c["status"] == "partial"; assert not c["modes"]["isolated"]["available"]'
  '';

  meta = {
    description = "Partial per-command VPN execution for macOS";
    mainProgram = "in-vpn";
    platforms = [ "aarch64-darwin" ];
    license = lib.licenses.mit;
    homepage = "https://github.com/yuidvg/in-vpn";
  };
}
