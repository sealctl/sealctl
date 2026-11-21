{
  description = "sealctl — hardware-wallet backed encryption: volumes, backups, secrets, SSH";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAll = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
      version = (builtins.fromTOML (builtins.readFile ./Cargo.toml)).workspace.package.version;
    in
    {
      packages = forAll (pkgs: rec {
        sealctl = pkgs.rustPlatform.buildRustPackage {
          pname = "sealctl";
          inherit version;
          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;
          cargoBuildFlags = [ "-p" "sealctl" ];
          # integration tests need hdiutil / sudo + cryptsetup; unit tests only here
          cargoTestFlags = [ "-p" "sealctl" "-p" "sealctl-ledger" "--lib" ];
          nativeBuildInputs = [ pkgs.pkg-config pkgs.installShellFiles ];
          buildInputs = pkgs.lib.optionals pkgs.stdenv.isLinux [ pkgs.udev pkgs.dbus ];
          postInstall = ''
            installShellCompletion --cmd sealctl \
              --bash <($out/bin/sealctl completions bash) \
              --zsh <($out/bin/sealctl completions zsh) \
              --fish <($out/bin/sealctl completions fish)
          '';
          meta = with pkgs.lib; {
            description = "Hardware-wallet backed encryption: volumes, backups, secrets, SSH";
            homepage = "https://github.com/sealctl/sealctl";
            license = licenses.mit;
            mainProgram = "sealctl";
            platforms = platforms.unix;
          };
        };
        default = sealctl;
      });

      apps = forAll (pkgs: {
        default = {
          type = "app";
          program = "${self.packages.${pkgs.system}.sealctl}/bin/sealctl";
        };
      });
    };
}
