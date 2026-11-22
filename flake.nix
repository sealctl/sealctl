{
  description = "sealctl — phone-approved keys: secrets, SSH, git signing, volumes, backups";

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
          # integration tests need hdiutil and the fake relay; unit tests only here
          cargoTestFlags = [ "-p" "sealctl" "-p" "sealctl-core" "--lib" ];
          nativeBuildInputs = [ pkgs.installShellFiles ];
          postInstall = ''
            installShellCompletion --cmd sealctl \
              --bash <($out/bin/sealctl completions bash) \
              --zsh <($out/bin/sealctl completions zsh) \
              --fish <($out/bin/sealctl completions fish)
            install -Dm644 THIRD-PARTY-NOTICES.md $out/share/doc/sealctl/THIRD-PARTY-NOTICES.md
          '';
          meta = with pkgs.lib; {
            description = "Phone-approved keys: secrets kept from AI agents, SSH, git signing, volumes, backups";
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
