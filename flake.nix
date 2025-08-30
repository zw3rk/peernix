{
  description = "org.zw3rk.peernix - P2P Nix store sharing for macOS";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
  };

  outputs = { self, nixpkgs, flake-parts, ... }@inputs:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [ "x86_64-darwin" "aarch64-darwin" ];
      perSystem = { config, system, ... }:
        let
          pkgs = import nixpkgs { inherit system; };
        in
        {
          packages.default = pkgs.buildGoModule {
            name = "org.zw3rk.peernix";
            src = ./.;
            vendorHash = null; # No external Go deps
            subPackages = [ "." ];
            buildInputs = [ ]; #pkgs.darwin.apple_sdk.frameworks.SystemConfiguration ];
            installPhase = ''
              runHook preInstall
              mkdir -p $out/bin
              cp $GOPATH/bin/peernix $out/bin/peernix
              mkdir -p $out/Library/LaunchDaemons
              cat <<EOF > $out/Library/LaunchDaemons/org.zw3rk.peernix.plist
              <?xml version="1.0" encoding="UTF-8"?>
              <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
              <plist version="1.0">
              <dict>
                <key>Label</key>
                <string>org.zw3rk.peernix</string>
                <key>ProgramArguments</key>
                <array>
                  <string>$out/bin/peernix</string>
                </array>
                <key>RunAtLoad</key>
                <true/>
                <key>KeepAlive</key>
                <true/>
              </dict>
              </plist>
              EOF
              mkdir -p $out/etc/nix
              echo "substituters = http://127.0.0.1:9999/nix-cache/" >> $out/etc/nix/nix.conf
              runHook postInstall
            '';
          };
          
          apps.default = {
            type = "app";
            program = "${config.packages.default}/bin/peernix";
          };
        };
    };
}