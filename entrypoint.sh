#!/bin/bash
set -e
mkdir -p /app/data
# Panel generates xray config and starts both
exec python main.py
