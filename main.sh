#!/bin/bash

# EXIFTron Multi-Tool Bash Wrapper
# Author: @Kdairatchii

# Configuration
TOOL_NAME="EXIFTron - MultiTool By Kdairatchi "
EXIF_SCRIPT="exiftron2.py"  # Ensure this is in the same directory
BANNER="
███████╗██╗██╗   ██╗████████╗████████╗██████╗ ██████╗ ███╗   ██╗
██╔════╝██║██║   ██║╚══██╔══╝╚══██╔══╝██╔══██╗██╔══██╗████╗  ██║
███████╗██║██║   ██║   ██║      ██║   ██████╔╝██████╔╝██╔██╗ ██║
╚════██║██║██║   ██║   ██║      ██║   ██╔═══╝ ██╔═══╝ ██║╚██╗██║
███████║██║╚██████╔╝   ██║      ██║   ██║     ██║     ██║ ╚████║
╚══════╝╚═╝ ╚═════╝    ╚═╝      ╚═╝   ╚═╝     ╚═╝     ╚═╝  ╚═══╝
"

# Check dependencies
check_dependencies() {
    echo -e "\n🔍 Checking dependencies..."
    deps=("python3" "exiftool" "waybackurls" "waymore" "ffmpeg")
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            echo -e "❌ Missing: $dep"
            echo -e "Installing $dep..."
            sudo apt install -y "$dep" || sudo brew install "$dep"
        else
            echo -e "✅ $dep installed!"
        fi
    done
}

# Launch the main menu
main_menu() {
    clear
    echo -e "$BANNER"
    echo -e "💀 Welcome to $TOOL_NAME 💀"
    echo -e "-------------------------------------"
    echo -e "1️⃣  Scan an Image for EXIF Data"
    echo -e "2️⃣  Extract EXIF from a URL"
    echo -e "3️⃣  Scan an Entire Domain for Images"
    echo -e "4️⃣  Download & Extract Images from Wayback Machine"
    echo -e "5️⃣  Batch Process a Folder of Images"
    echo -e "6️⃣  Inject Payload into EXIF Metadata"
    echo -e "7️⃣  Clean EXIF Metadata from an Image"
    echo -e "8️⃣  Generate Full EXIF Security Report"
    echo -e "9️⃣  🔄 Update Tool"
    echo -e "0️⃣  🚪 Exit"
    echo -e "-------------------------------------"
    
    read -p "👉 Select an option: " option
    case $option in
        1) scan_image ;;
        2) extract_exif_url ;;
        3) scan_domain ;;
        4) download_wayback_images ;;
        5) batch_process ;;
        6) inject_payload ;;
        7) clean_exif ;;
        8) generate_report ;;
        9) update_tool ;;
        0) exit 0 ;;
        *) echo -e "❌ Invalid option. Try again!" && sleep 1 && main_menu ;;
    esac
}

# Scan a single image
scan_image() {
    read -p "🖼️ Enter image file path: " image
    python3 "$EXIF_SCRIPT" -i "$image" -e
    echo -e "✅ EXIF Data Extracted!"
    read -p "Press Enter to continue..."
    main_menu
}

# Extract EXIF from an image URL
extract_exif_url() {
    read -p "🌍 Enter image URL: " url
    python3 "$EXIF_SCRIPT" -u "$url" -e
    echo -e "✅ EXIF Data Extracted!"
    read -p "Press Enter to continue..."
    main_menu
}

# Scan a domain for images
scan_domain() {
    read -p "🔎 Enter target domain (e.g., example.com): " domain
    python3 "$EXIF_SCRIPT" -d "$domain"
    echo -e "✅ Domain Scanning Complete!"
    read -p "Press Enter to continue..."
    main_menu
}

# Download & extract images from Wayback Machine
download_wayback_images() {
    read -p "📡 Enter target domain: " domain
    python3 "$EXIF_SCRIPT" -w -d "$domain"
    echo -e "✅ Wayback Machine Data Extracted!"
    read -p "Press Enter to continue..."
    main_menu
}

# Batch process a folder of images
batch_process() {
    read -p "📁 Enter folder path: " folder
    python3 "$EXIF_SCRIPT" -b "$folder" -e
    echo -e "✅ Batch Processing Complete!"
    read -p "Press Enter to continue..."
    main_menu
}

# Inject Payload into EXIF Metadata
inject_payload() {
    read -p "💉 Enter image file path: " image
    read -p "🔥 Enter payload type (xss/sqli/rce): " payload
    python3 "$EXIF_SCRIPT" -i "$image" -a -p "$payload"
    echo -e "✅ Payload Injected!"
    read -p "Press Enter to continue..."
    main_menu
}

# Clean EXIF Metadata
clean_exif() {
    read -p "🧹 Enter image file path: " image
    python3 "$EXIF_SCRIPT" -i "$image" -c
    echo -e "✅ EXIF Data Removed!"
    read -p "Press Enter to continue..."
    main_menu
}

# Generate Full EXIF Security Report
generate_report() {
    read -p "📊 Enter target domain: " domain
    python3 "$EXIF_SCRIPT" -d "$domain" --report
    echo -e "✅ Report Generated!"
    read -p "Press Enter to continue..."
    main_menu
}

# Update the tool
update_tool() {
    echo -e "🔄 Updating EXIFTron..."
    git pull origin main
    chmod +x main.sh
    echo -e "✅ Update Complete!"
    read -p "Press Enter to continue..."
    main_menu
}

# Run the tool
check_dependencies
main_menu
