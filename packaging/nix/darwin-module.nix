{ self }:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.programs.invpn;
  system = pkgs.stdenv.hostPlatform.system;
in
{
  options.programs.invpn = {
    enable = lib.mkEnableOption "the InVPN partial CLI";
    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${system}.invpn or self.packages.aarch64-darwin.invpn;
      defaultText = lib.literalExpression "inputs.invpn.packages.\${pkgs.stdenv.hostPlatform.system}.invpn";
      description = "InVPN CLI with its qualified Python and sing-box dependencies.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = system == "aarch64-darwin";
        message = "InVPN 0.1.0 supports Apple Silicon macOS (aarch64-darwin) only.";
      }
    ];
    environment.systemPackages = [ cfg.package ];
  };
}
