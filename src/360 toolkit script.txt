#!/usr/bin/env python3
"""
Automated Forensic Toolkit using Sleuth Kit
A user-friendly interface for digital forensics analysis
"""

import subprocess
import json
import csv
import os
import sys
from datetime import datetime
from pathlib import Path
import argparse

class ForensicToolkit:
    """Main class for the automated forensic toolkit"""
    
    def __init__(self, image_path, output_dir="forensic_output"):
        self.image_path = image_path
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.results = {
            "analysis_date": datetime.now().isoformat(),
            "image_analyzed": str(image_path),
            "artifacts": {}
        }
    
    def run_command(self, cmd):
        """Execute a shell command and return output"""
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=300
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return "", "Command timed out", -1
        except Exception as e:
            return "", str(e), -1
    
    def analyze_filesystem(self):
        """Analyze filesystem structure using fsstat"""
        print("[*] Analyzing filesystem structure...")
        cmd = f"fsstat {self.image_path}"
        stdout, stderr, code = self.run_command(cmd)
        
        if code == 0:
            self.results["artifacts"]["filesystem_info"] = {
                "raw_output": stdout,
                "status": "success"
            }
            self._save_text_output("filesystem_info.txt", stdout)
            print("[✓] Filesystem analysis complete")
        else:
            print(f"[✗] Filesystem analysis failed: {stderr}")
            self.results["artifacts"]["filesystem_info"] = {
                "status": "failed",
                "error": stderr
            }
        
        return stdout
    
    def list_files(self, recursive=True):
        """List all files using fls"""
        print("[*] Extracting file listing...")
        flag = "-r" if recursive else ""
        cmd = f"fls {flag} -m / {self.image_path}"
        stdout, stderr, code = self.run_command(cmd)
        
        if code == 0:
            files = self._parse_fls_output(stdout)
            self.results["artifacts"]["file_listing"] = {
                "total_files": len(files),
                "files": files,
                "status": "success"
            }
            self._save_csv_output("file_listing.csv", files)
            print(f"[✓] Found {len(files)} files")
        else:
            print(f"[✗] File listing failed: {stderr}")
            self.results["artifacts"]["file_listing"] = {
                "status": "failed",
                "error": stderr
            }
        
        return files if code == 0 else []
    
    def _parse_fls_output(self, output):
        """Parse fls output into structured data"""
        files = []
        for line in output.strip().split('\n'):
            if not line or line.startswith('#'):
                continue
            parts = line.split('|')
            if len(parts) >= 10:
                files.append({
                    "type": parts[1],
                    "inode": parts[2],
                    "name": parts[3],
                    "mode": parts[4],
                    "uid": parts[5],
                    "gid": parts[6],
                    "size": parts[7],
                    "atime": parts[8],
                    "mtime": parts[9],
                    "ctime": parts[10] if len(parts) > 10 else ""
                })
        return files
    
    def analyze_file_metadata(self, inode):
        """Get detailed metadata for a specific file using istat"""
        print(f"[*] Analyzing metadata for inode {inode}...")
        cmd = f"istat {self.image_path} {inode}"
        stdout, stderr, code = self.run_command(cmd)
        
        if code == 0:
            print(f"[✓] Metadata extracted for inode {inode}")
            return stdout
        else:
            print(f"[✗] Metadata extraction failed: {stderr}")
            return None
    
    def extract_deleted_files(self):
        """Find deleted files"""
        print("[*] Searching for deleted files...")
        cmd = f"fls -r -d {self.image_path}"
        stdout, stderr, code = self.run_command(cmd)
        
        if code == 0:
            deleted_files = [line for line in stdout.split('\n') if line.strip()]
            self.results["artifacts"]["deleted_files"] = {
                "count": len(deleted_files),
                "files": deleted_files,
                "status": "success"
            }
            self._save_text_output("deleted_files.txt", stdout)
            print(f"[✓] Found {len(deleted_files)} deleted files")
        else:
            print(f"[✗] Deleted file search failed: {stderr}")
            self.results["artifacts"]["deleted_files"] = {
                "status": "failed",
                "error": stderr
            }
        
        return deleted_files if code == 0 else []
    
    def create_timeline(self):
        """Generate filesystem timeline using fls"""
        print("[*] Creating filesystem timeline...")
        cmd = f"fls -r -m / {self.image_path}"
        stdout, stderr, code = self.run_command(cmd)
        
        if code == 0:
            timeline_entries = stdout.strip().split('\n')
            self.results["artifacts"]["timeline"] = {
                "entries": len(timeline_entries),
                "status": "success"
            }
            self._save_text_output("timeline.txt", stdout)
            print(f"[✓] Timeline created with {len(timeline_entries)} entries")
        else:
            print(f"[✗] Timeline creation failed: {stderr}")
            self.results["artifacts"]["timeline"] = {
                "status": "failed",
                "error": stderr
            }
    
    def analyze_partitions(self):
        """Analyze disk partitions using mmls"""
        print("[*] Analyzing disk partitions...")
        cmd = f"mmls {self.image_path}"
        stdout, stderr, code = self.run_command(cmd)
        
        if code == 0:
            partitions = self._parse_mmls_output(stdout)
            self.results["artifacts"]["partitions"] = {
                "count": len(partitions),
                "partitions": partitions,
                "status": "success"
            }
            self._save_csv_output("partitions.csv", partitions)
            print(f"[✓] Found {len(partitions)} partitions")
        else:
            print(f"[✗] Partition analysis failed: {stderr}")
            self.results["artifacts"]["partitions"] = {
                "status": "failed",
                "error": stderr
            }
    
    def _parse_mmls_output(self, output):
        """Parse mmls output into structured data"""
        partitions = []
        lines = output.strip().split('\n')
        for line in lines:
            if line.startswith('0') or not line[0].isdigit():
                continue
            parts = line.split()
            if len(parts) >= 6:
                partitions.append({
                    "slot": parts[0],
                    "start": parts[1],
                    "end": parts[2],
                    "length": parts[3],
                    "description": ' '.join(parts[4:])
                })
        return partitions
    
    def recover_file(self, inode, output_filename):
        """Recover a file by inode using icat"""
        print(f"[*] Recovering file inode {inode}...")
        output_path = self.output_dir / "recovered" / output_filename
        output_path.parent.mkdir(exist_ok=True)
        
        cmd = f"icat {self.image_path} {inode} > {output_path}"
        stdout, stderr, code = self.run_command(cmd)
        
        if code == 0:
            print(f"[✓] File recovered to {output_path}")
            return str(output_path)
        else:
            print(f"[✗] File recovery failed: {stderr}")
            return None
    
    def _save_text_output(self, filename, content):
        """Save text output to file"""
        filepath = self.output_dir / f"{self.timestamp}_{filename}"
        with open(filepath, 'w') as f:
            f.write(content)
    
    def _save_csv_output(self, filename, data):
        """Save data as CSV"""
        if not data:
            return
        filepath = self.output_dir / f"{self.timestamp}_{filename}"
        with open(filepath, 'w', newline='') as f:
            if isinstance(data[0], dict):
                writer = csv.DictWriter(f, fieldnames=data[0].keys())
                writer.writeheader()
                writer.writerows(data)
    
    def save_json_report(self):
        """Save complete analysis results as JSON"""
        filepath = self.output_dir / f"{self.timestamp}_forensic_report.json"
        with open(filepath, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"\n[✓] JSON report saved to {filepath}")
    
    def run_full_analysis(self):
        """Execute complete forensic analysis workflow"""
        print(f"\n{'='*60}")
        print(f"Automated Forensic Analysis Starting")
        print(f"Image: {self.image_path}")
        print(f"Output Directory: {self.output_dir}")
        print(f"{'='*60}\n")
        
        # Run all analysis modules
        self.analyze_partitions()
        self.analyze_filesystem()
        self.list_files()
        self.extract_deleted_files()
        self.create_timeline()
        
        # Save comprehensive report
        self.save_json_report()
        
        print(f"\n{'='*60}")
        print(f"Analysis Complete!")
        print(f"{'='*60}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Automated Forensic Toolkit using Sleuth Kit"
    )
    parser.add_argument(
        "image",
        help="Path to disk image file"
    )
    parser.add_argument(
        "-o", "--output",
        default="forensic_output",
        help="Output directory (default: forensic_output)"
    )
    parser.add_argument(
        "-m", "--module",
        choices=["full", "filesystem", "files", "deleted", "timeline", "partitions"],
        default="full",
        help="Analysis module to run (default: full)"
    )
    
    args = parser.parse_args()
    
    # Check if image exists
    if not os.path.exists(args.image):
        print(f"[✗] Error: Image file '{args.image}' not found")
        sys.exit(1)
    
    # Initialize toolkit
    toolkit = ForensicToolkit(args.image, args.output)
    
    # Run selected analysis
    if args.module == "full":
        toolkit.run_full_analysis()
    elif args.module == "filesystem":
        toolkit.analyze_filesystem()
        toolkit.save_json_report()
    elif args.module == "files":
        toolkit.list_files()
        toolkit.save_json_report()
    elif args.module == "deleted":
        toolkit.extract_deleted_files()
        toolkit.save_json_report()
    elif args.module == "timeline":
        toolkit.create_timeline()
        toolkit.save_json_report()
    elif args.module == "partitions":
        toolkit.analyze_partitions()
        toolkit.save_json_report()


if __name__ == "__main__":
    main()
