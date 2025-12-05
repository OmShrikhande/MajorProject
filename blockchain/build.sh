#!/bin/bash

echo "=========================================="
echo "Building Blockchain Audit Log API Server"
echo "=========================================="

# Install dependencies
echo "Installing dependencies..."
npm ci --production

# Verify server.js exists
if [ ! -f "server.js" ]; then
  echo "ERROR: server.js not found!"
  exit 1
fi

echo "Build completed successfully"
echo "Ready to start with: npm start"
