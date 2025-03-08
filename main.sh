#!/usr/bin/env bash
# Ultimate EXIFTron Multi-Tool Menu
# Author: @Kdairatchi

# Configuration
TOOL_NAME="Ultimate EXIFTron"
EXIF_SCRIPT="exiftron.py"  # Path to your Python EXIFTron script
RESULTS_DB="${HOME}/.exiftron_results.db"
TEMP_DIR=$(mktemp -d)
GIT_REPO_URL="https://github.com/kdairatchi/exiftron.git"  # Update with your repository URL

# Color Codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
BOLD='\033[1m'
RESET='\033[0m'

# Banner (ASCII art)
BANNER="${PURPLE}
 ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
 ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
 ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
 ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
 ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
${RESET}"

# Dependency Check Function
check_dependencies() {
    local deps=("python3" "exiftool" "git")
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &>/dev/null; then
            echo -e "${RED}[!] Missing dependency: $dep${RESET}"
            exit 1
        fi
    done
}

# Update Tool Function
update_tool() {
    echo -e "${CYAN}${BOLD}[➔]${RESET} Updating $TOOL_NAME..."
    git pull origin main || { echo -e "${RED}Update failed!${RESET}"; exit 1; }
    echo -e "${GREEN}${BOLD}[✓]${RESET} Update Complete!"
    sleep 2
}

# Main Menu
main_menu() {
    clear
    echo -e "$BANNER"
    echo -e "${CYAN}${BOLD}Welcome to $TOOL_NAME${RESET}"
    echo -e "-------------------------------------"
    echo -e "1️⃣  Scan an Image for EXIF Data"
    echo -e "2️⃣  Extract EXIF from an Image URL"
    echo -e "3️⃣  Scan an Entire Domain for Images"
    echo -e "4️⃣  Download & Extract Images from Wayback Machine"
    echo -e "5️⃣  Batch Process a Folder of Images"
    echo -e "6️⃣  Inject Payload into EXIF Metadata"
    echo -e "7️⃣  Clean EXIF Metadata from an Image"
    echo -e "8️⃣  Generate Full EXIF Security Report"
    echo -e "9️⃣  Launch Custom Dashboard"
    echo -e "🔟  Generate Test Image (PoC)"
    echo -e "11️⃣  Update Tool"
    echo -e "0️⃣  Exit"
    echo -e "-------------------------------------"
    read -p "👉 Select an option: " option
    case $option in
        1) scan_image ;;
        2) extract_exif_url ;;
        3) scan_domain ;;
        4) download_wayback_images ;;
        5) batch_process_menu ;;
        6) inject_payload_menu ;;
        7) clean_exif ;;
        8) generate_report_menu ;;
        9) launch_dashboard ;;
        10) generate_test_image ;;
        11) update_tool; main_menu ;;
        0) cleanup; exit 0 ;;
        *) echo -e "${RED}❌ Invalid option. Try again!${RESET}" && sleep 1 && main_menu ;;
    esac
}

# Scan a Single Image
scan_image() {
    read -p "🖼️ Enter image file path: " image
    python3 "$EXIF_SCRIPT" -i "$image" -e
    echo -e "${GREEN}[✓] EXIF Data Extracted!${RESET}"
    read -p "Press Enter to continue..."
    main_menu
}

# Extract EXIF from an Image URL
extract_exif_url() {
    read -p "🌍 Enter image URL: " url
    python3 "$EXIF_SCRIPT" -u "$url" -e
    echo -e "${GREEN}[✓] EXIF Data Extracted!${RESET}"
    read -p "Press Enter to continue..."
    main_menu
}

# Scan a Domain for Images (Placeholder for future implementation)
scan_domain() {
    read -p "🔎 Enter target domain (e.g., example.com): " domain
    python3 "$EXIF_SCRIPT" -d "$domain"
    echo -e "${GREEN}[✓] Domain Scanning Complete!${RESET}"
    read -p "Press Enter to continue..."
    main_menu
}

# Download & Extract Images from Wayback Machine (Placeholder for future implementation)
download_wayback_images() {
    read -p "📡 Enter target domain: " domain
    python3 "$EXIF_SCRIPT" -w -d "$domain"
    echo -e "${GREEN}[✓] Wayback Machine Data Extracted!${RESET}"
    read -p "Press Enter to continue..."
    main_menu
}

# Batch Process a Folder of Images
batch_process_menu() {
    read -p "📁 Enter folder path: " folder
    python3 "$EXIF_SCRIPT" -b "$folder" -e
    echo -e "${GREEN}[✓] Batch Processing Complete!${RESET}"
    read -p "Press Enter to continue..."
    main_menu
}

# Inject Payload into EXIF Metadata
inject_payload_menu() {
    read -p "💉 Enter image file path: " image
    read -p "🔥 Enter payload type (XSS, SQLi, RCE, LDAP, XXE): " payload
    read -p "🔧 Enter target field (default Comment): " field
    field=${field:-Comment}
    python3 "$EXIF_SCRIPT" -i "$image" -p "$payload" -f "$field" -a
    echo -e "${GREEN}[✓] Payload Injected!${RESET}"
    read -p "Press Enter to continue..."
    main_menu
}

# Clean EXIF Metadata from an Image
clean_exif() {
    read -p "🧹 Enter image file path: " image
    python3 "$EXIF_SCRIPT" -i "$image" -c
    echo -e "${GREEN}[✓] EXIF Data Removed!${RESET}"
    read -p "Press Enter to continue..."
    main_menu
}

# Generate Full EXIF Security Report
generate_report_menu() {
    read -p "📊 Enter target domain (or folder path for batch): " target
    # Here, we assume domain scanning is a placeholder; for batch, pass -b
    if [[ -d "$target" ]]; then
        python3 "$EXIF_SCRIPT" -b "$target" --report
    else
        python3 "$EXIF_SCRIPT" -d "$target" --report
    fi
    echo -e "${GREEN}[✓] Report Generated!${RESET}"
    read -p "Press Enter to continue..."
    main_menu
}

# Launch the Web Dashboard
launch_dashboard() {
    # For dashboard, assume batch mode results are needed.
    read -p "📁 Enter folder path for dashboard (batch mode): " folder
    python3 "$EXIF_SCRIPT" -b "$folder" --dashboard
    read -p "Press Enter to continue..."
    main_menu
}

# Generate a Test Image with PoC Payloads
generate_test_image() {
    python3 "$EXIF_SCRIPT" --test
    read -p "Press Enter to continue..."
    main_menu
}

# Cleanup temporary resources if needed
cleanup() {
    rm -rf "$TEMP_DIR"
}

# Run dependency check and then main menu
check_dependencies
main_menu
