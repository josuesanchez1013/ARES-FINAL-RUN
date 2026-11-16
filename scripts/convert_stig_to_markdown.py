r"""
STIG XML to Markdown Converter

Converts STIG XCCDF XML files to Markdown format for Genesis RAG upload.
Genesis RAG accepts markdown but not XML, so we convert the STIG documentation
to a format suitable for vector database ingestion.

Usage:
    python scripts/convert_stig_to_markdown.py --xml <path_to_xml> --output <output_md_path>

Example:
    python scripts/convert_stig_to_markdown.py --xml "C:\path\to\U_RHEL_8_V2R7_Manual-xccdf.xml" --output "data/input/RHEL_8_STIG_V2R7.md"
"""

import xml.etree.ElementTree as ET
import argparse
import os
import sys
from pathlib import Path


def convert_stig_xml_to_markdown(xml_path: str, output_path: str) -> None:
    """
    Convert STIG XCCDF XML to Markdown for Genesis RAG upload.
    
    Args:
        xml_path: Path to STIG XML file
        output_path: Path for output Markdown file
        
    Raises:
        FileNotFoundError: If XML file doesn't exist
        ET.ParseError: If XML is malformed
    """
    
    # Validate input file exists
    if not os.path.exists(xml_path):
        raise FileNotFoundError(f"STIG XML file not found: {xml_path}")
    
    print(f"[1/4] Reading STIG XML: {xml_path}")
    
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except ET.ParseError as e:
        raise ET.ParseError(f"Failed to parse STIG XML: {e}")
    
    # XCCDF namespace handling
    # STIG files use NIST XCCDF 1.1 or 1.2 namespace
    ns = {
        'xccdf': 'http://checklists.nist.gov/xccdf/1.1',
        'xccdf-1.2': 'http://checklists.nist.gov/xccdf/1.2',
        'dc': 'http://purl.org/dc/elements/1.1/'
    }
    
    print("[2/4] Extracting STIG metadata and rules...")
    
    # Start building markdown content
    markdown_lines = []
    
    # Extract STIG metadata from Benchmark element (root IS the benchmark in XCCDF 1.1)
    benchmark = root if root.tag.endswith('Benchmark') else root.find('xccdf:Benchmark', ns)
    if benchmark is None:
        benchmark = root.find('xccdf-1.2:Benchmark', ns) or root
    
    title = benchmark.find('xccdf:title', ns)
    if title is None:
        title = benchmark.find('xccdf-1.2:title', ns)
    
    version = benchmark.find('xccdf:version', ns)
    if version is None:
        version = benchmark.find('xccdf-1.2:version', ns)
    
    release_info = benchmark.find('xccdf:plain-text[@id="release-info"]', ns)
    if release_info is None:
        release_info = benchmark.find('xccdf-1.2:plain-text[@id="release-info"]', ns)
    
    # Write header with comprehensive metadata
    markdown_lines.append("# STIG Documentation - Converted for Genesis RAG\n\n")
    
    stig_name = title.text if title is not None else "Unknown STIG"
    markdown_lines.append(f"**STIG Name:** {stig_name}\n\n")
    
    if version is not None:
        # Version element has version number in text
        version_num = version.text or "Unknown"
        markdown_lines.append(f"**Version:** {version_num}\n\n")
    
    if release_info is not None:
        release_text = release_info.text or ""
        # Extract release number from "Release: 7 Benchmark Date: 01 Apr 2026"
        if "Release:" in release_text:
            release_num = release_text.split("Release:")[1].split("Benchmark")[0].strip()
            markdown_lines.append(f"**Release:** {release_num}\n\n")
        markdown_lines.append(f"**Release Info:** {release_text}\n\n")
        # Try to extract benchmark date
        if "Benchmark Date:" in release_text:
            benchmark_date = release_text.split("Benchmark Date:")[-1].strip()
            markdown_lines.append(f"**Benchmark Date:** {benchmark_date}\n\n")
    
    markdown_lines.append("---\n\n")
    markdown_lines.append("# STIG Rules and Requirements\n\n")
    markdown_lines.append("This document contains all STIG rules with complete metadata and Check Text for validation.\n\n")
    markdown_lines.append("**CRITICAL:** Gap Coverage and Determination agents must use Discussion and Check Text fields for analysis.\n")
    markdown_lines.append("**WARNING:** Agents must NEVER execute commands from Fix Text - Fix Text is for remediation only, not validation.\n\n")
    markdown_lines.append("---\n\n")
    
    # Extract all Groups (each Group contains a Rule)
    groups = root.findall('xccdf:Group', ns)
    if not groups:
        groups = root.findall('xccdf-1.2:Group', ns)
    
    rule_count = 0
    for group in groups:
        rule = group.find('xccdf:Rule', ns)
        if rule is None:
            rule = group.find('xccdf-1.2:Rule', ns)
        if rule is None:
            continue
        
        rule_count += 1
        
        # Extract IDs
        group_id = group.get('id', 'Unknown')  # e.g., V-230221
        rule_id = rule.get('id', 'Unknown')     # e.g., SV-230221r1017040_rule
        severity = rule.get('severity', 'medium')  # low, medium, high
        
        # Map severity to CAT levels
        severity_map = {'low': 'CAT III', 'medium': 'CAT II', 'high': 'CAT I'}
        severity_cat = severity_map.get(severity.lower(), severity.upper())
        
        # Extract STIG ID from rule version element
        rule_version = rule.find('xccdf:version', ns)
        if rule_version is None:
            rule_version = rule.find('xccdf-1.2:version', ns)
        stig_id = rule_version.text if rule_version is not None else "Unknown"
        
        # Extract idents for CCI
        idents = rule.findall('xccdf:ident', ns)
        if not idents:
            idents = rule.findall('xccdf-1.2:ident', ns)
        cci_list = []
        for ident in idents:
            ident_system = ident.get('system', '')
            ident_text = ident.text or ""
            # CCI IDs are in cyber.mil/cci system
            if 'cyber.mil/cci' in ident_system.lower() or ident_text.startswith('CCI-'):
                cci_list.append(ident_text)
        
        # Extract rule elements
        rule_title = rule.find('xccdf:title', ns)
        if rule_title is None:
            rule_title = rule.find('xccdf-1.2:title', ns)
        
        rule_description = rule.find('xccdf:description', ns)
        if rule_description is None:
            rule_description = rule.find('xccdf-1.2:description', ns)
        
        # Extract VulnDiscussion from description
        discussion = ""
        if rule_description is not None:
            desc_text = ''.join(rule_description.itertext())
            # Extract VulnDiscussion section
            if '<VulnDiscussion>' in desc_text:
                discussion = desc_text.split('<VulnDiscussion>')[1].split('</VulnDiscussion>')[0].strip()
            else:
                discussion = desc_text.strip()
        
        # Check content is crucial for Gap Coverage and Determination agents
        check = rule.find('xccdf:check', ns)
        if check is None:
            check = rule.find('xccdf-1.2:check', ns)
        
        check_text = ""
        if check is not None:
            check_content = check.find('xccdf:check-content', ns)
            if check_content is None:
                check_content = check.find('xccdf-1.2:check-content', ns)
            if check_content is not None:
                # Use itertext() to get all text including child elements
                check_text = ''.join(check_content.itertext()).strip()
        
        # Fix text for remediation (agents must NEVER execute this)
        fix_text = ""
        fixtext = rule.find('xccdf:fixtext', ns)
        if fixtext is None:
            fixtext = rule.find('xccdf-1.2:fixtext', ns)
        if fixtext is not None:
            fix_text = ''.join(fixtext.itertext()).strip()
        
        # Format as Markdown with all fields
        markdown_lines.append(f"## {group_id}\n\n")
        markdown_lines.append(f"**Group ID (Vuln ID):** {group_id}\n\n")
        markdown_lines.append(f"**Rule ID:** {rule_id}\n\n")
        markdown_lines.append(f"**STIG ID:** {stig_id}\n\n")
        markdown_lines.append(f"**Severity:** {severity_cat}\n\n")
        markdown_lines.append(f"**Classification:** Unclassified\n\n")  # STIG Viewer default
        
        if rule_title is not None:
            title_text = rule_title.text or ""
            markdown_lines.append(f"**Rule Title:** {title_text}\n\n")
        
        if discussion:
            markdown_lines.append(f"**Discussion:**\n{discussion}\n\n")
        
        # CRITICAL: Check Text contains validation commands
        if check_text:
            markdown_lines.append(f"**Check Text:**\n```\n{check_text}\n```\n\n")
        else:
            markdown_lines.append(f"**Check Text:** Not specified\n\n")
        
        # Fix Text for context (agents must NEVER execute)
        if fix_text:
            markdown_lines.append(f"**Fix Text:**\n```\n{fix_text}\n```\n\n")
        
        # Add CCIs if available
        if cci_list:
            markdown_lines.append(f"**CCI:** {', '.join(cci_list)}\n\n")
        
        markdown_lines.append("---\n\n")
    
    print(f"[3/4] Extracted {rule_count} STIG rules")
    
    # Write to output file
    print(f"[4/4] Writing Markdown to: {output_path}")
    
    # Ensure output directory exists
    output_dir = Path(output_path).parent
    output_dir.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.writelines(markdown_lines)
    
    print(f"\n✅ SUCCESS: Converted {rule_count} STIG rules to Markdown")
    print(f"📄 Output file: {output_path}")
    print(f"📊 File size: {os.path.getsize(output_path) / 1024:.2f} KB")
    print(f"\n📤 Next step: Upload {os.path.basename(output_path)} to Genesis agents:")
    print(f"   - Gap Coverage Agent (RAG Tool Mode)")
    print(f"   - Determination Agent (RAG Tool Mode)")


def main():
    parser = argparse.ArgumentParser(
        description="Convert STIG XCCDF XML to Markdown for Genesis RAG upload",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scripts/convert_stig_to_markdown.py \\
    --xml "C:\\path\\to\\U_RHEL_8_V2R7_Manual-xccdf.xml" \\
    --output "data/input/RHEL_8_STIG_V2R7.md"
  
  python scripts/convert_stig_to_markdown.py \\
    --xml "/mnt/c/stig/U_RHEL_8_V2R7_Manual-xccdf.xml" \\
    --output "data/input/RHEL_8_STIG_V2R7.md"
        """
    )
    
    parser.add_argument(
        "--xml",
        required=True,
        help="Path to STIG XCCDF XML file"
    )
    
    parser.add_argument(
        "--output",
        required=True,
        help="Path for output Markdown file"
    )
    
    args = parser.parse_args()
    
    try:
        convert_stig_xml_to_markdown(args.xml, args.output)
    except Exception as e:
        print(f"\n❌ ERROR: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
