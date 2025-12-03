#!/usr/bin/env python3
"""
Interactive Menu Interface for Automated Forensic Toolkit
User-friendly frontend for Sleuth Kit operations
"""

import os
import sys
from pathlib import Path

def clear_screen():
    """Clear the terminal screen"""
    os.system('clear' if os.name == 'posix' else 'cls')

def print_banner():
    """Display toolkit banner"""
    banner = """
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║        Automated Forensic Toolkit v1.0                   ║
    ║        Powered by Sleuth Kit                             ║
    ║                                                           ║
    ║        Making Digital Forensics Faster & Easier          ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
    """
    print(banner)

def print_menu():
    """Display main menu options"""
    menu = """
    ┌─── MAIN MENU ──────────────────────────────────────────┐
    │                                                         │
    │  [1] Load Disk Image                                   │
    │  [2] Analyze Filesystem Structure                      │
    │  [3] List All Files                                    │
    │  [4] Search for Deleted Files                          │
    │  [5] Generate Timeline                                 │
    │  [6] Analyze Disk Partitions                           │
    │  [7] Get File Metadata (by inode)                      │
    │  [8] Recover File (by inode)                           │
    │  [9] Run Complete Analysis                             │
    │  [0] Generate Final Report                             │
    │                                                         │
    │  [h] Help & Documentation                              │
    │  [q] Quit                                              │
    │                                                         │
    └─────────────────────────────────────────────────────────┘
    """
    print(menu)

def show_help():
    """Display help information"""
    help_text = """
    ╔═══════════════════════════════════════════════════════════╗
    ║                     HELP & USAGE                          ║
    ╚═══════════════════════════════════════════════════════════╝
    
    ABOUT THIS TOOL:
    This toolkit automates Sleuth Kit commands for digital forensics.
    It parses outputs into clean CSV/JSON files for easy analysis.
    
    WORKFLOW:
    1. Load a disk image file (option 1)
    2. Choose individual analysis modules (2-8)
       OR run complete analysis (option 9)
    3. Review outputs in the 'forensic_output' directory
    4. Generate final JSON report (option 0)
    
    OUTPUT FILES:
    • CSV files - structured data for spreadsheets
    • JSON files - complete forensic report
    • TXT files - raw Sleuth Kit outputs
    
    SUPPORTED IMAGE FORMATS:
    • Raw (.dd, .raw, .img)
    • E01 (Expert Witness Format)
    • AFF (Advanced Forensic Format)
    
    REQUIREMENTS:
    • Sleuth Kit must be installed
    • Python 3.6 or higher
    • Read permissions for disk images
    
    COMMON USE CASES:
    → Lab assignments: Run option 9 for complete analysis
    → Deleted file recovery: Use options 4 → 7 → 8
    → Timeline analysis: Use option 5
    → Partition examination: Use option 6
    """
    print(help_text)
    input("\nPress Enter to continue...")

def load_image():
    """Prompt user to load disk image"""
    print("\n┌─── LOAD DISK IMAGE ────────────────────────────────────┐")
    print("│ Enter the path to your disk image file                │")
    print("│ Supported formats: .dd, .raw, .img, .e01, .aff        │")
    print("└────────────────────────────────────────────────────────┘\n")
    
    while True:
        image_path = input("Image path (or 'back' to return): ").strip()
        
        if image_path.lower() == 'back':
            return None
        
        if os.path.exists(image_path):
            print(f"\n[✓] Image loaded successfully: {image_path}")
            input("\nPress Enter to continue...")
            return image_path
        else:
            print(f"\n[✗] Error: File not found - {image_path}")
            retry = input("Try again? (y/n): ").strip().lower()
            if retry != 'y':
                return None

def get_output_directory():
    """Get or create output directory"""
    default_dir = "forensic_output"
    print(f"\nOutput directory (default: {default_dir}): ", end="")
    custom_dir = input().strip()
    
    output_dir = custom_dir if custom_dir else default_dir
    Path(output_dir).mkdir(exist_ok=True)
    return output_dir

def run_analysis_module(toolkit, module_name):
    """Execute a specific analysis module"""
    clear_screen()
    print(f"\n{'='*60}")
    print(f"Running: {module_name}")
    print(f"{'='*60}\n")
    
    modules = {
        "filesystem": toolkit.analyze_filesystem,
        "files": toolkit.list_files,
        "deleted": toolkit.extract_deleted_files,
        "timeline": toolkit.create_timeline,
        "partitions": toolkit.analyze_partitions
    }
    
    if module_name in modules:
        modules[module_name]()
        toolkit.save_json_report()
    
    print(f"\n{'='*60}")
    input("\nPress Enter to continue...")

def get_inode_input():
    """Get inode number from user"""
    while True:
        inode = input("\nEnter inode number (or 'back' to return): ").strip()
        if inode.lower() == 'back':
            return None
        if inode.isdigit():
            return inode
        print("[✗] Invalid inode. Please enter a number.")

def main_loop():
    """Main interactive loop"""
    toolkit = None
    image_path = None
    output_dir = None
    
    while True:
        clear_screen()
        print_banner()
        
        # Show current image status
        if image_path:
            print(f"    Current Image: {image_path}")
            print(f"    Output Directory: {output_dir}")
        else:
            print("    ⚠  No disk image loaded - please load an image first")
        
        print_menu()
        
        choice = input("\n    Select option: ").strip().lower()
        
        if choice == 'q':
            print("\n    Thank you for using Automated Forensic Toolkit!")
            print("    Goodbye!\n")
            sys.exit(0)
        
        elif choice == 'h':
            clear_screen()
            show_help()
        
        elif choice == '1':
            image_path = load_image()
            if image_path:
                output_dir = get_output_directory()
                # Import here to avoid issues if module not available initially
                from forensic_toolkit import ForensicToolkit
                toolkit = ForensicToolkit(image_path, output_dir)
        
        elif choice in ['2', '3', '4', '5', '6', '9']:
            if not toolkit:
                print("\n    [✗] Please load a disk image first (option 1)")
                input("\n    Press Enter to continue...")
                continue
            
            module_map = {
                '2': 'filesystem',
                '3': 'files',
                '4': 'deleted',
                '5': 'timeline',
                '6': 'partitions'
            }
            
            if choice == '9':
                clear_screen()
                print("\n" + "="*60)
                print("Running Complete Forensic Analysis")
                print("This will execute all analysis modules...")
                print("="*60 + "\n")
                confirm = input("Continue? (y/n): ").strip().lower()
                if confirm == 'y':
                    toolkit.run_full_analysis()
                    input("\nPress Enter to continue...")
            else:
                module = module_map[choice]
                run_analysis_module(toolkit, module)
        
        elif choice == '7':
            if not toolkit:
                print("\n    [✗] Please load a disk image first (option 1)")
                input("\n    Press Enter to continue...")
                continue
            
            inode = get_inode_input()
            if inode:
                clear_screen()
                print("\n" + "="*60)
                metadata = toolkit.analyze_file_metadata(inode)
                if metadata:
                    print(metadata)
                print("="*60)
                input("\nPress Enter to continue...")
        
        elif choice == '8':
            if not toolkit:
                print("\n    [✗] Please load a disk image first (option 1)")
                input("\n    Press Enter to continue...")
                continue
            
            inode = get_inode_input()
            if inode:
                filename = input("Output filename: ").strip()
                if filename:
                    clear_screen()
                    recovered = toolkit.recover_file(inode, filename)
                    if recovered:
                        print(f"\n[✓] File recovered to: {recovered}")
                    input("\nPress Enter to continue...")
        
        elif choice == '0':
            if not toolkit:
                print("\n    [✗] Please load a disk image first (option 1)")
                input("\n    Press Enter to continue...")
                continue
            
            clear_screen()
            print("\n" + "="*60)
            print("Generating Final Forensic Report...")
            print("="*60 + "\n")
            toolkit.save_json_report()
            input("\nPress Enter to continue...")
        
        else:
            print("\n    [✗] Invalid option. Please try again.")
            input("\n    Press Enter to continue...")


if __name__ == "__main__":
    try:
        main_loop()
    except KeyboardInterrupt:
        print("\n\n    Operation cancelled by user. Goodbye!\n")
        sys.exit(0)
