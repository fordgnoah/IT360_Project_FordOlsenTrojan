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
        
        # Check for high entropy warnings in stderr
        if stderr and "high entropy" in stderr.lower():
            print("[!] Note: High entropy/encrypted files detected (this is informational)")
            self.results["warnings"] = self.results.get("warnings", [])
            self.results["warnings"].append("High entropy files detected - may indicate encryption or compression")
        
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
            
            # Categorize deleted files by recoverability
            recoverable = []
            realloc_warning = []
            
            for file_entry in deleted_files:
                if '(realloc)' in file_entry:
                    realloc_warning.append(file_entry)
                else:
                    recoverable.append(file_entry)
            
            self.results["artifacts"]["deleted_files"] = {
                "count": len(deleted_files),
                "recoverable_count": len(recoverable),
                "realloc_count": len(realloc_warning),
                "files": deleted_files,
                "recoverable": recoverable,
                "realloc_warning": realloc_warning,
                "status": "success"
            }
            
            self._save_text_output("deleted_files.txt", stdout)
            
            # Save categorized deleted files
            if recoverable:
                self._save_text_output("deleted_files_recoverable.txt", '\n'.join(recoverable))
            if realloc_warning:
                self._save_text_output("deleted_files_realloc.txt", '\n'.join(realloc_warning))
            
            print(f"[✓] Found {len(deleted_files)} deleted files")
            print(f"    ├─ {len(recoverable)} potentially recoverable")
            print(f"    └─ {len(realloc_warning)} with reallocation warnings (may be overwritten)")
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
    
    def generate_html_report(self):
        """Generate a professional HTML report"""
        filepath = self.output_dir / f"{self.timestamp}_forensic_report.html"
        
        html_content = self._build_html_report()
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"[✓] HTML report saved to {filepath}")
        return filepath
    
    def _build_html_report(self):
        """Build the HTML report content"""
        # Get summary statistics
        total_files = self.results.get("artifacts", {}).get("file_listing", {}).get("total_files", 0)
        deleted_count = self.results.get("artifacts", {}).get("deleted_files", {}).get("count", 0)
        recoverable_count = self.results.get("artifacts", {}).get("deleted_files", {}).get("recoverable_count", 0)
        realloc_count = self.results.get("artifacts", {}).get("deleted_files", {}).get("realloc_count", 0)
        partition_count = self.results.get("artifacts", {}).get("partitions", {}).get("count", 0)
        timeline_entries = self.results.get("artifacts", {}).get("timeline", {}).get("entries", 0)
        
        # Get file listing
        files = self.results.get("artifacts", {}).get("file_listing", {}).get("files", [])
        
        # Get partitions
        partitions = self.results.get("artifacts", {}).get("partitions", {}).get("partitions", [])
        
        # Get filesystem info
        fs_info = self.results.get("artifacts", {}).get("filesystem_info", {}).get("raw_output", "N/A")
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Forensic Analysis Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            line-height: 1.6;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #2d3748 0%, #1a202c 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }}
        
        .header .subtitle {{
            font-size: 1.1em;
            opacity: 0.9;
            margin-top: 10px;
        }}
        
        .meta-info {{
            background: #f7fafc;
            padding: 25px 40px;
            border-bottom: 3px solid #e2e8f0;
        }}
        
        .meta-info p {{
            margin: 8px 0;
            color: #4a5568;
            font-size: 0.95em;
        }}
        
        .meta-info strong {{
            color: #2d3748;
            font-weight: 600;
        }}
        
        .content {{
            padding: 40px;
        }}
        
        .summary-cards {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }}
        
        .card {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 25px;
            border-radius: 12px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }}
        
        .card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 8px 25px rgba(0,0,0,0.2);
        }}
        
        .card h3 {{
            font-size: 0.9em;
            opacity: 0.9;
            margin-bottom: 10px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        
        .card .number {{
            font-size: 3em;
            font-weight: bold;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.2);
        }}
        
        .card.success {{
            background: linear-gradient(135deg, #48bb78 0%, #38a169 100%);
        }}
        
        .card.warning {{
            background: linear-gradient(135deg, #ed8936 0%, #dd6b20 100%);
        }}
        
        .card.info {{
            background: linear-gradient(135deg, #4299e1 0%, #3182ce 100%);
        }}
        
        .section {{
            margin-bottom: 40px;
        }}
        
        .section h2 {{
            color: #2d3748;
            font-size: 1.8em;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 3px solid #667eea;
            display: flex;
            align-items: center;
        }}
        
        .section h2::before {{
            content: "▶";
            margin-right: 10px;
            color: #667eea;
        }}
        
        .table-container {{
            overflow-x: auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.08);
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.9em;
        }}
        
        thead {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }}
        
        thead th {{
            padding: 15px;
            text-align: left;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.85em;
            letter-spacing: 0.5px;
        }}
        
        tbody tr {{
            border-bottom: 1px solid #e2e8f0;
            transition: background-color 0.2s ease;
        }}
        
        tbody tr:hover {{
            background-color: #f7fafc;
        }}
        
        tbody td {{
            padding: 12px 15px;
            color: #4a5568;
        }}
        
        tbody tr:nth-child(even) {{
            background-color: #fafafa;
        }}
        
        .badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 600;
        }}
        
        .badge.success {{
            background: #c6f6d5;
            color: #22543d;
        }}
        
        .badge.error {{
            background: #fed7d7;
            color: #742a2a;
        }}
        
        .code-block {{
            background: #2d3748;
            color: #e2e8f0;
            padding: 20px;
            border-radius: 8px;
            overflow-x: auto;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            line-height: 1.6;
            white-space: pre-wrap;
            word-wrap: break-word;
            box-shadow: inset 0 2px 10px rgba(0,0,0,0.3);
        }}
        
        .footer {{
            background: #f7fafc;
            padding: 30px;
            text-align: center;
            color: #718096;
            border-top: 3px solid #e2e8f0;
        }}
        
        .footer p {{
            margin: 5px 0;
        }}
        
        .no-data {{
            text-align: center;
            padding: 40px;
            color: #a0aec0;
            font-style: italic;
        }}
        
        .pagination-info {{
            margin-top: 20px;
            padding: 15px;
            background: #edf2f7;
            border-radius: 8px;
            text-align: center;
            color: #4a5568;
        }}
        
        @media print {{
            body {{
                background: white;
                padding: 0;
            }}
            
            .container {{
                box-shadow: none;
            }}
            
            .card {{
                break-inside: avoid;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Digital Forensic Analysis Report</h1>
            <p class="subtitle">Automated Forensic Toolkit - Powered by Sleuth Kit</p>
        </div>
        
        <div class="meta-info">
            <p><strong>Analysis Date:</strong> {self.results.get('analysis_date', 'N/A')}</p>
            <p><strong>Image Analyzed:</strong> {self.results.get('image_analyzed', 'N/A')}</p>
            <p><strong>Output Directory:</strong> {self.output_dir}</p>
            <p><strong>Report Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="content">
            <div class="summary-cards">
                <div class="card success">
                    <h3>Total Files</h3>
                    <div class="number">{total_files:,}</div>
                </div>
                
                <div class="card warning">
                    <h3>Deleted Files</h3>
                    <div class="number">{deleted_count:,}</div>
                </div>
                
                <div class="card info">
                    <h3>Partitions</h3>
                    <div class="number">{partition_count}</div>
                </div>
                
                <div class="card">
                    <h3>Timeline Entries</h3>
                    <div class="number">{timeline_entries:,}</div>
                </div>
            </div>
            
            {f'''
            <div class="section">
                <h2>Deleted Files Recovery Analysis</h2>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Category</th>
                                <th>Count</th>
                                <th>Status</th>
                                <th>Description</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td><strong>Total Deleted</strong></td>
                                <td>{deleted_count}</td>
                                <td><span class="badge warning">DELETED</span></td>
                                <td>All files found in deleted state</td>
                            </tr>
                            <tr>
                                <td><strong>Potentially Recoverable</strong></td>
                                <td>{recoverable_count}</td>
                                <td><span class="badge success">RECOVERABLE</span></td>
                                <td>Files with intact metadata, good recovery chance</td>
                            </tr>
                            <tr>
                                <td><strong>Reallocated (Warning)</strong></td>
                                <td>{realloc_count}</td>
                                <td><span class="badge error">OVERWRITTEN</span></td>
                                <td>Metadata reused by another file, likely overwritten</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
                <div style="margin-top: 20px; padding: 15px; background: #fff3cd; border-left: 4px solid #ffc107; border-radius: 4px;">
                    <strong>⚠️ Note about "realloc" files:</strong>
                    <p style="margin: 10px 0 0 0; color: #856404;">
                        Files marked with "(realloc)" have had their metadata structures reallocated to new files. 
                        This means the original file data has likely been overwritten and cannot be recovered. 
                        Focus recovery efforts on files without the realloc indicator.
                    </p>
                </div>
            </div>
            ''' if deleted_count > 0 else ''}
"""

        # Partition Information
        if partitions:
            html += """
            <div class="section">
                <h2>Disk Partitions</h2>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Slot</th>
                                <th>Start Sector</th>
                                <th>End Sector</th>
                                <th>Length</th>
                                <th>Description</th>
                            </tr>
                        </thead>
                        <tbody>
"""
            for partition in partitions:
                html += f"""
                            <tr>
                                <td>{partition.get('slot', 'N/A')}</td>
                                <td>{partition.get('start', 'N/A')}</td>
                                <td>{partition.get('end', 'N/A')}</td>
                                <td>{partition.get('length', 'N/A')}</td>
                                <td>{partition.get('description', 'N/A')}</td>
                            </tr>
"""
            html += """
                        </tbody>
                    </table>
                </div>
            </div>
"""

        # Filesystem Information
        html += f"""
            <div class="section">
                <h2>Filesystem Information</h2>
                <div class="code-block">{fs_info[:2000] if fs_info != "N/A" else "No filesystem information available"}</div>
            </div>
"""

        # File Listing (show first 100 files)
        if files:
            display_files = files[:100]
            html += f"""
            <div class="section">
                <h2>File Listing</h2>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Type</th>
                                <th>Inode</th>
                                <th>Name</th>
                                <th>Size</th>
                                <th>Modified Time</th>
                                <th>Permissions</th>
                            </tr>
                        </thead>
                        <tbody>
"""
            for file in display_files:
                html += f"""
                            <tr>
                                <td>{file.get('type', 'N/A')}</td>
                                <td>{file.get('inode', 'N/A')}</td>
                                <td style="word-break: break-all;">{file.get('name', 'N/A')}</td>
                                <td>{file.get('size', 'N/A')}</td>
                                <td>{file.get('mtime', 'N/A')}</td>
                                <td><code>{file.get('mode', 'N/A')}</code></td>
                            </tr>
"""
            html += """
                        </tbody>
                    </table>
                </div>
"""
            if len(files) > 100:
                html += f"""
                <div class="pagination-info">
                    Showing first 100 of {len(files):,} files. 
                    See the CSV export for the complete file listing.
                </div>
"""
            html += """
            </div>
"""

        # Analysis Status Summary
        html += """
            <div class="section">
                <h2>Analysis Module Status</h2>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Module</th>
                                <th>Status</th>
                                <th>Details</th>
                            </tr>
                        </thead>
                        <tbody>
"""
        
        artifacts = self.results.get("artifacts", {})
        for module_name, module_data in artifacts.items():
            if isinstance(module_data, dict):
                status = module_data.get("status", "unknown")
                badge_class = "success" if status == "success" else "error"
                
                # Create detail string
                details = []
                if "total_files" in module_data:
                    details.append(f"{module_data['total_files']:,} files")
                if "count" in module_data:
                    details.append(f"{module_data['count']} items")
                if "entries" in module_data:
                    details.append(f"{module_data['entries']:,} entries")
                detail_str = ", ".join(details) if details else "Completed"
                
                html += f"""
                            <tr>
                                <td><strong>{module_name.replace('_', ' ').title()}</strong></td>
                                <td><span class="badge {badge_class}">{status.upper()}</span></td>
                                <td>{detail_str}</td>
                            </tr>
"""
        
        html += """
                        </tbody>
                    </table>
                </div>
            </div>
"""

        # Footer
        html += f"""
        </div>
        
        <div class="footer">
            <p><strong>Automated Forensic Toolkit v1.0</strong></p>
            <p>Powered by Sleuth Kit | Generated by Ford, Olsen, Trojan</p>
            <p>Report generated on {datetime.now().strftime('%B %d, %Y at %H:%M:%S')}</p>
        </div>
    </div>
</body>
</html>
"""
        return html
    
    def run_full_analysis(self, generate_html=True):
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
        
        # Save comprehensive reports
        self.save_json_report()
        
        if generate_html:
            print()
            html_path = self.generate_html_report()
            print(f"\n[i] Open the HTML report in your browser:")
            print(f"    file://{html_path.absolute()}")
        
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
    parser.add_argument(
        "--html",
        action="store_true",
        help="Generate HTML report (default: True for full analysis)"
    )
    parser.add_argument(
        "--no-html",
        action="store_true",
        help="Skip HTML report generation"
    )
    
    args = parser.parse_args()
    
    # Check if image exists
    if not os.path.exists(args.image):
        print(f"[✗] Error: Image file '{args.image}' not found")
        sys.exit(1)
    
    # Initialize toolkit
    toolkit = ForensicToolkit(args.image, args.output)
    
    # Determine if HTML should be generated
    generate_html = args.html or (args.module == "full" and not args.no_html)
    
    # Run selected analysis
    if args.module == "full":
        toolkit.run_full_analysis(generate_html=generate_html)
    elif args.module == "filesystem":
        toolkit.analyze_filesystem()
        toolkit.save_json_report()
        if generate_html:
            toolkit.generate_html_report()
    elif args.module == "files":
        toolkit.list_files()
        toolkit.save_json_report()
        if generate_html:
            toolkit.generate_html_report()
    elif args.module == "deleted":
        toolkit.extract_deleted_files()
        toolkit.save_json_report()
        if generate_html:
            toolkit.generate_html_report()
    elif args.module == "timeline":
        toolkit.create_timeline()
        toolkit.save_json_report()
        if generate_html:
            toolkit.generate_html_report()
    elif args.module == "partitions":
        toolkit.analyze_partitions()
        toolkit.save_json_report()
        if generate_html:
            toolkit.generate_html_report()


if __name__ == "__main__":
    main()
