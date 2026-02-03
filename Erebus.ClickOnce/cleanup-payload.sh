#!/bin/bash
# Cleanup script to minimize payload per SpecterOps methodology
# Removes unnecessary files, keeping only the loader executable

PUBLISH_DIR="${1:-bin/Release/net7.0-windows/win-x64/publish}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PUBLISH_PATH="$SCRIPT_DIR/$PUBLISH_DIR"

if [ ! -d "$PUBLISH_PATH" ]; then
    echo "Error: Publish directory not found: $PUBLISH_PATH" >&2
    exit 1
fi

echo -e "\e[36m[*] Cleaning payload directory: $PUBLISH_PATH\e[0m"

# Unnecessary extensions to remove
unnecessary_exts=(".pdb" ".deps.json" ".runtimeconfig.json" ".xml" ".dll" ".json")

has_unnecessary_ext() {
    local filename="$1"
    for ext in "${unnecessary_exts[@]}"; do
        if [[ "$filename" == *"$ext" ]]; then
            return 0
        fi
    done
    return 1
}

# Clean directory - keep only .exe files
echo -e "\n\e[33m[*] Cleaning publish directory...\e[0m"
while IFS= read -r -d '' file; do
    filename=$(basename "$file")
    
    if [[ "$filename" == *.exe ]]; then
        echo -e "  \e[32m[+] Keeping: $filename\e[0m"
    elif has_unnecessary_ext "$filename"; then
        echo -e "  \e[31m[-] Removing: $filename\e[0m"
        rm -f "$file"
    else
        echo -e "  \e[31m[-] Removing: $filename\e[0m"
        rm -f "$file"
    fi
done < <(find "$PUBLISH_PATH" -maxdepth 1 -type f -print0)

echo -e "\n\e[32m[+] Cleanup complete!\e[0m"
echo -e "\n\e[36m[*] Final payload:\e[0m"

# Display final files with sizes
find "$PUBLISH_PATH" -maxdepth 1 -type f | while read -r item; do
    filename=$(basename "$item")
    size=$(du -h "$item" | cut -f1)
    echo -e "  [FILE] $filename ($size)"
done