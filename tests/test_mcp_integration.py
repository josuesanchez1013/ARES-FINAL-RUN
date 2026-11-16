"""
Integration test for MCP v1.3.0 complete workflow:
1. Upload CKL/CSV file to MCP server
2. Parse file via MCP tools (Genesis Agent simulation)
3. Download parsed JSON file
4. Validate Gap Identifier integration

This validates the complete file-based architecture end-to-end.

Usage: python -m pytest tests/test_mcp_integration.py -v
   Or: python tests/test_mcp_integration.py (standalone)
"""

import requests
import json
from pathlib import Path
import sys
import urllib3
import pytest

# These target the (retired) OpenShift MCP endpoint and hit the network; they are
# opt-in integration tests, deselected by default. To be rewritten for the local
# packaged MCP in Phase 2.
pytestmark = pytest.mark.integration

# Disable SSL warnings for self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Add project root to path for imports
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from genesis_integration.gap_identifier import identify_gaps_from_files, load_findings_from_file

MCP_URL = "https://mcp.example.internal"


def test_upload_file(filepath: str):
    """Test file upload endpoint"""
    print(f"\n{'='*60}")
    print(f"TEST 1: Upload file to MCP server")
    print(f"{'='*60}")
    print(f"Uploading: {filepath}")
    
    with open(filepath, 'rb') as f:
        files = {'file': (Path(filepath).name, f)}
        response = requests.post(f"{MCP_URL}/api/upload", files=files, verify=False)
    
    if response.status_code == 200:
        result = response.json()
        print(f"✅ Upload successful!")
        print(f"   Filename: {result['filename']}")
        print(f"   Path on server: {result['path']}")
        print(f"   Size: {result['size_bytes']} bytes")
        return result
    else:
        print(f"❌ Upload failed: {response.status_code}")
        print(f"   Error: {response.text}")
        return None


def test_mcp_parse(filepath: str, tool_type: str):
    """
    Simulate Genesis Agent calling MCP tool.
    In production, Genesis would do this via MCP protocol.
    """
    print(f"\n{'='*60}")
    print(f"TEST 2: Parse file via MCP tool (simulated)")
    print(f"{'='*60}")
    print(f"Tool: parse_{tool_type}")
    print(f"Input: {filepath}")
    print(f"\nNOTE: Genesis Agent would call this via MCP protocol.")
    print(f"For now, we'll verify the workflow manually:")
    print(f"1. File uploaded to: {filepath}")
    print(f"2. Genesis Agent would call: parse_{tool_type}('{filepath}')")
    print(f"3. Tool would parse and write to /tmp/data/output/{{filename}}_parsed.json")
    print(f"4. Tool returns metadata only (not full JSON)")
    
    # Expected output filename
    input_filename = Path(filepath).stem
    expected_output = f"{input_filename}_parsed.json"
    
    return expected_output


def test_download_parsed(filename: str):
    """Test downloading parsed JSON file"""
    print(f"\n{'='*60}")
    print(f"TEST 3: Download parsed file via REST API")
    print(f"{'='*60}")
    print(f"Downloading: {filename}")
    
    response = requests.get(f"{MCP_URL}/api/files/{filename}", verify=False)
    
    if response.status_code == 200:
        data = response.json()
        print(f"✅ Download successful!")
        print(f"   Findings count: {len(data.get('findings', []))}")
        
        # Save to local temp file for gap identifier testing
        local_path = Path(f"temp_{filename}")
        with open(local_path, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"   Saved to: {local_path}")
        return str(local_path)
    else:
        print(f"❌ Download failed: {response.status_code}")
        print(f"   Error: {response.text}")
        print(f"\n⚠️  This is expected if MCP tool hasn't been called yet.")
        print(f"   We need to manually trigger parse or wait for Genesis agent.")
        return None


def test_gap_identifier(file1: str, file2: str = None):
    """Test Gap Identifier with downloaded files"""
    print(f"\n{'='*60}")
    print(f"TEST 4: Gap Identifier with parsed files")
    print(f"{'='*60}")
    
    if not file2:
        # Test with single file (load and validate structure)
        print(f"Loading single file: {file1}")
        try:
            findings = load_findings_from_file(file1)
            print(f"✅ File loaded successfully!")
            print(f"   Findings count: {len(findings)}")
            print(f"   First finding status: {findings[0].get('status', 'N/A') if findings else 'N/A'}")
            return True
        except Exception as e:
            print(f"❌ Gap Identifier failed: {str(e)}")
            return False
    else:
        # Test with two files (full gap detection)
        print(f"File 1: {file1}")
        print(f"File 2: {file2}")
        try:
            result = identify_gaps_from_files(file1, file2)
            gaps = result['gaps']
            stats = result['stats']
            print(f"✅ Gap identification successful!")
            print(f"   Gaps found: {stats['total_gaps']}")
            print(f"   Tool1 only: {stats['tool1_only_count']}")
            print(f"   Tool2 only: {stats['tool2_only_count']}")
            print(f"   Both missing: {stats['both_missing_count']}")
            return True
        except Exception as e:
            print(f"❌ Gap Identifier failed: {str(e)}")
            return False


def test_health_check():
    """Test health endpoint"""
    print(f"\n{'='*60}")
    print(f"TEST 0: Health Check")
    print(f"{'='*60}")
    
    response = requests.get(f"{MCP_URL}/api/health", verify=False)
    
    if response.status_code == 200:
        data = response.json()
        print(f"✅ MCP Server is healthy!")
        print(f"   Version: {data.get('version')}")
        print(f"   MCP Protocol: {data.get('services', {}).get('mcp_protocol')}")
        print(f"   REST API: {data.get('services', {}).get('rest_api')}")
        return True
    else:
        print(f"❌ Health check failed: {response.status_code}")
        return False


def main():
    """Run full workflow test"""
    print("\n" + "="*60)
    print("MCP v1.3.0 INTEGRATION TEST")
    print("="*60)
    
    # Check if test data exists (relative to project root)
    test_ckl = PROJECT_ROOT / "data/input/rhel8-prestige-auto.ckl"
    test_csv = PROJECT_ROOT / "data/input/rhel8-evaluatestig-auto.csv"
    
    if not test_ckl.exists():
        print(f"❌ Test file not found: {test_ckl}")
        print("   Please ensure test data exists in data/input/")
        return
    
    # Test 0: Health check
    if not test_health_check():
        print("\n❌ MCP server not responding. Aborting tests.")
        return
    
    # Test 1: Upload file
    upload_result = test_upload_file(str(test_ckl))
    if not upload_result:
        print("\n❌ Upload failed. Aborting tests.")
        return
    
    # Test 2: Simulate parse (explain manual step)
    expected_output = test_mcp_parse(upload_result['path'], 'ckl')
    
    # Test 3: Download parsed file (may not exist yet)
    print(f"\n⚠️  Skipping download test - requires Genesis Agent to call parse tool")
    print(f"   Expected output file: {expected_output}")
    print(f"   Manual step: Call Genesis Parser Agent with filepath: {upload_result['path']}")
    
    # Test 4: Summary
    print(f"\n{'='*60}")
    print(f"WORKFLOW VALIDATION COMPLETE")
    print(f"{'='*60}")
    print(f"✅ File upload endpoint working")
    print(f"⏳ Parse step requires Genesis Agent call")
    print(f"⏳ Download step requires parsed file to exist")
    print(f"⏳ Gap Identifier step requires two parsed files")
    print(f"\nNext steps:")
    print(f"1. Call Genesis Parser Agent with: {upload_result['path']}")
    print(f"2. Verify file written to /tmp/data/output/{expected_output}")
    print(f"3. Download via: GET {MCP_URL}/api/files/{expected_output}")
    print(f"4. Test Gap Identifier with downloaded files")


if __name__ == "__main__":
    main()
