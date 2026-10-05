#!/bin/bash
# Build the current tree the way Homebrew builds the formula (its build
# environment and sandbox), through a throwaway local tap. Homebrew cannot load
# Swift macro plugins, so SwiftUI code that builds with `make` may not build here.
set -euo pipefail

cd "$(dirname "$0")/.."
work=$(mktemp -d)
tap="local/egressguard-check"
export HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_INSTALL_FROM_API=1 HOMEBREW_NO_ANALYTICS=1
cleanup() {
  brew uninstall --force egressguard-check >/dev/null 2>&1 || true
  brew untap "$tap" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

revision=$(git stash create)
git archive --prefix=egressguard-check/ -o "$work/source.tar.gz" "${revision:-HEAD}"
brew tap-new --no-git "$tap" >/dev/null
formula="$(brew --repository)/Library/Taps/local/homebrew-egressguard-check/Formula/egressguard-check.rb"
mkdir -p "$(dirname "$formula")"
cat > "$formula" <<FORMULA
class EgressguardCheck < Formula
  desc "Build check of the egressguard working tree"
  homepage "https://github.com/sentiens/egressguard"
  url "file://$work/source.tar.gz"
  sha256 "$(shasum -a 256 "$work/source.tar.gz" | cut -d' ' -f1)"
  version "0"
  license "MIT"
  keg_only "it is a build check"
  depends_on "go" => :build
  def install
    system "make", "install", "PREFIX=#{prefix}"
  end
end
FORMULA
brew install --build-from-source "$tap/egressguard-check"
"$(brew --prefix egressguard-check)/bin/egressguard" version
test -x "$(brew --prefix egressguard-check)/EgressGuard.app/Contents/MacOS/EgressGuard"
echo "the Homebrew build works"
