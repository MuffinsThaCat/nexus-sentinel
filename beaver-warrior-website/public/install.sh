#!/bin/bash
set -e

echo "🦫 Installing Beaver Warrior..."
echo ""

# Detect platform
OS=$(uname -s)
ARCH=$(uname -m)

if [ "$OS" != "Darwin" ]; then
  echo "❌ Currently only macOS is supported. Linux and Windows coming soon."
  exit 1
fi

# Create install directory
INSTALL_DIR="$HOME/.beaver-warrior"
mkdir -p "$INSTALL_DIR"

# Download
echo "⬇️  Downloading..."
curl -fsSL "https://beaverwarrior.com/BeaverWarrior-macOS.zip" -o "/tmp/BeaverWarrior-macOS.zip"

# Extract
echo "📦 Extracting..."
unzip -qo "/tmp/BeaverWarrior-macOS.zip" -d "/tmp/"

# Install
cp /tmp/BeaverWarrior/BeaverWarrior "$INSTALL_DIR/BeaverWarrior"
cp /tmp/BeaverWarrior/sentinel.toml "$INSTALL_DIR/sentinel.toml"
chmod +x "$INSTALL_DIR/BeaverWarrior"
xattr -cr "$INSTALL_DIR/" 2>/dev/null || true

# Cleanup
rm -rf /tmp/BeaverWarrior /tmp/BeaverWarrior-macOS.zip

# Add to PATH if not already there
if ! echo "$PATH" | grep -q "$INSTALL_DIR"; then
  SHELL_RC="$HOME/.zshrc"
  [ -f "$HOME/.bashrc" ] && [ ! -f "$HOME/.zshrc" ] && SHELL_RC="$HOME/.bashrc"
  echo "" >> "$SHELL_RC"
  echo "# Beaver Warrior" >> "$SHELL_RC"
  echo "export PATH=\"\$HOME/.beaver-warrior:\$PATH\"" >> "$SHELL_RC"
  echo "📎 Added to PATH in $SHELL_RC"
fi

echo ""
echo "✅ Beaver Warrior installed to $INSTALL_DIR/BeaverWarrior"
echo ""
echo "To start:"
echo "  $INSTALL_DIR/BeaverWarrior"
echo ""
echo "Or open a new terminal and run:"
echo "  BeaverWarrior"
echo ""
echo "Dashboard will be available at http://127.0.0.1:9090"
echo ""
echo "🦫 Your machine. Your data. Your rules."
