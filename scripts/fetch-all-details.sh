#!/bin/bash
set -euo pipefail

if [ ! -d "./data" ]; then
    mkdir -p "./data"
fi

DATA_DIR="./data"
download_and_extract() {
    URL=$1
    DEST=$2
    echo "downloading $URL ==> "
    mkdir -p "$DEST"           # Ensure the destination directory exists
    curl -L "$URL" | tar -xz --strip-components=1 -C "$DEST"
}

download_and_extract_zip() {
    URL=$1
    DEST=$2
    echo "downloading $URL ==> "
    curl -L "$URL" -o "$DEST/temp.zip"
    unzip -o "$DEST/temp.zip" -d "$DEST"
    rm "$DEST/temp.zip"
}

ifsc=$(curl -s https://api.github.com/repos/razorpay/ifsc/releases/latest | grep "browser_download_url" | grep "by-bank.tar.gz" | sed -E 's/.*"([^"]+)".*/\1/')
wordnet="https://wordnetcode.princeton.edu/3.0/WNdb-3.0.tar.gz"
cities15000="http://download.geonames.org/export/dump/cities15000.zip"

download_and_extract "$ifsc" "$DATA_DIR/ifsc"
download_and_extract "$wordnet" "$DATA_DIR/wordnet"
download_and_extract_zip "$cities15000" "$DATA_DIR"