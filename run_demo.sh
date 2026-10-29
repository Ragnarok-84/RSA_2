#!/usr/bin/env bash
# macOS / Linux: tạo .venv (nếu chưa có), cài thư viện, mở GUI.
set -e
cd "$(dirname "$0")"
if [ ! -d .venv ]; then
    python3 -m venv .venv
fi
. .venv/bin/activate
python -m pip install --upgrade pip -q
python -m pip install -r requirements.txt -q
python -m demo.gui
