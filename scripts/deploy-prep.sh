#!/bin/bash
set -e

echo "═══════════════════════════════════════════════════"
echo "  Nexus Sentinel — Deployment Preparation"
echo "═══════════════════════════════════════════════════"
echo ""

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# ── Step 1: Build License Server ──────────────────────
echo "▸ Building license server (release)..."
cd "$ROOT"
cargo build --release -p sentinel-license-server
echo "  ✓ License server binary: target/release/license-server"
echo ""

# ── Step 2: Build Desktop App ─────────────────────────
echo "▸ Building desktop app..."
cd "$ROOT/sentinel-desktop/frontend"

if [ ! -d "node_modules" ]; then
    echo "  Installing npm dependencies..."
    npm install
fi

echo "  Building Tauri app (this may take a few minutes)..."
npm run tauri build

echo "  ✓ Desktop app built!"
echo ""

# ── Step 3: Show outputs ─────────────────────────────
echo "═══════════════════════════════════════════════════"
echo "  Build Complete!"
echo "═══════════════════════════════════════════════════"
echo ""
echo "License Server Binary:"
ls -lh "$ROOT/target/release/license-server" 2>/dev/null || echo "  (check target/release/)"
echo ""
echo "Desktop App Bundles:"
BUNDLE_DIR="$ROOT/sentinel-desktop/frontend/src-tauri/target/release/bundle"
if [ -d "$BUNDLE_DIR" ]; then
    find "$BUNDLE_DIR" -maxdepth 2 -type f \( -name "*.dmg" -o -name "*.msi" -o -name "*.deb" -o -name "*.AppImage" -o -name "*.app" \) 2>/dev/null | while read f; do
        echo "  $(ls -lh "$f" | awk '{print $5, $NF}')"
    done
fi
echo ""
echo "Next steps:"
echo "  1. Set up Stripe (see DEPLOY.md Part 1)"
echo "  2. Deploy license server (see DEPLOY.md Part 2)"
echo "  3. Edit config.json with your credentials (see DEPLOY.md Part 3)"
echo "  4. Distribute the desktop app to users"
echo ""
