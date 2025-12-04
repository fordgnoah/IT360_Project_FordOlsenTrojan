# IT360_Project_FordOlsenTrojan

Video Presentation link: https://youtu.be/HSV-VvqfCjo

Project Description:
Our semester project is to learn and establish the Kali tool Sleuth Kit, gaining knowledge and skills to develop our own custom tool kit. In return, we will have a tool that is automated to gather system information like file metadata, logs, and user activities.

Project Overview:
This project delivers an automated forensic analysis toolkit that uses Sleuth Kit as a backend service to perform comprehensive digital forensics investigations. Instead of manually typing dozens of commands and parsing raw text output, our tool automates the entire workflow and generates professional, organized reports.

# Core Forensic Capabilities  
1. Structured Data Exports  
- JSON: Complete machine-readable report  
- CSV: Spreadsheet-ready data tables  
- TXT: Raw Sleuth Kit outputs for validation
- HTML: Print-ready PDF  
2. Interactive Menu Interface  
- Helpful terminal UI  
- No command memorization needed  
3. One-Click Complete Analysis  
- Run all forensic modules with a single command
- Intelligent logging and error handling  
4. File Recovery (icat)  
- Recover files by inode number
- Extract deleted file contents while preserving original content
5. Metadata Extraction (istat)  
- Detailed inode information by number
- File attributes and extended metadata with timestamps
6. Partition Analysis (mmls)  
- Identify disk partitions and extract tables
7. Timeline Generation (fls -m)  
- Create a comprehensive activity timeline
- Track file access, modification, creation
8.  Intelligent Deleted File Discovery (fls -d)  
- Identify all deleted files
- Smart categorization shows if the file is recoverable or potentially overwritten
9. Comprehensive File Listing (fls)  
- Recursive directory traversal
- Extract all file metadata:
-   Times modified, accessed, or changed
-   File sizes and permissions
-   Owner UID/GID
-   Inode numbers
10. Filesystem Analysis (fsstat) 
-  Extract complete filesystem metadata
-  Identify filesystem type (ext2/3/4, NTFS, FAT32, etc.)
-  Document block size, inode information, volume details
  
# Setup Instructions
1. Install Sluethkit  
Ubuntu/Debian:
```
sudo apt update  
sudo apt install sleuthkit
```
macOS:
```
brew install sleuthkit
```
2. Clone Repository  
```
git clone https://github.com/fordgnoah/IT360_Project_FordOlsenTrojan.git
```
**DISCLAIMER - If the files are downloaded as .txt files, execute the following code.**
```
mv 360_toolkit_menu.txt toolkit_menu.py
mv 360_toolkit_script.txt toolkit_script.py
mv 360_toolkit2_menu_HTML.txt 360_toolkit2_menu_HTML.py
```

3. Set Permissions
```
chmod +x 360_toolkit_script.py
chmod +x 360_toolkit_menu.py
chmod +x 360_toolkit2_menu_HTML.py
chmod +x setup.sh
```
4. Verify Install
```
python3 --version    # Should be 3.6+
fls -V              # Should show Sleuth Kit version
```
5. Download Test Image (Optional)
   - The download for the test image we used is located in the 'data' folder of our repository.
  
# Quick Start
**Version 1**
```
cd forensic-toolkit

python3 360_toolkit_script.py

/path/to/disk-image.dd

python3 360_toolkit_menu.py
```
**Version 2**
```
cd forensic-toolkit

python3 360_toolkit2_Menu_HTML.py /path/to/disk-image.dd

ls -lh forensic_output/
```
You'll see:
- TIMESTAMP_forensic_report.html  (Open in browser!)
- TIMESTAMP_forensic_report.json
- TIMESTAMP_file_listing.csv
- TIMESTAMP_partitions.csv
- TIMESTAMP_deleted_files.txt
- And more...  

Open the HTML report
```
firefox forensic_output/*_forensic_report.html
```
