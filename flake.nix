{
  description = "InVPN partial CLI for macOS; fully isolated execution is unavailable";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/a7868a727837f3c09cee2ce0ca671c76b1589fed";

  outputs =
    { self, nixpkgs }:
    let
      system = "aarch64-darwin";
      pkgs = import nixpkgs { inherit system; };
      invpn = pkgs.callPackage ./packaging/nix/package.nix { };
    in
    {
      packages.${system} = {
        inherit invpn;
        default = invpn;
      };
      apps.${system} = {
        invpn = {
          type = "app";
          program = "${invpn}/bin/in-vpn";
          meta.description = "InVPN partial CLI";
        };
        default = self.apps.${system}.invpn;
      };
      checks.${system}.invpn = invpn;
      darwinModules.default = import ./packaging/nix/darwin-module.nix { inherit self; };
      formatter.${system} = pkgs.nixfmt;
    };
}
