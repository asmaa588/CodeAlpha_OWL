import ast
import re

def analyze_file(filename):
    with open(filename, 'r') as f:
        content = f.read()

    print(f"\n{'='*60}")
    print(f"🔍 Security Analysis Report: {filename}")
    print(f"{'='*60}\n")

    vulnerabilities = []

    # 1. SQL Injection
    if re.search(r'execute\s*\(\s*["\'].*\+', content) or \
       re.search(r'execute\s*\(f["\']', content):
        vulnerabilities.append({
            "id": "VULN-001",
            "type": "SQL Injection",
            "severity": "🔴 CRITICAL",
            "line": [i+1 for i, l in enumerate(content.split('\n')) if 'execute' in l and ('+' in l or 'f"' in l or "f'" in l)],
            "description": "User input directly concatenated into SQL query",
            "fix": "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE username = ?', (username,))"
        })

    # 2. Hardcoded Credentials
    if re.search(r'(PASSWORD|SECRET|KEY|TOKEN)\s*=\s*["\'].+["\']', content, re.IGNORECASE):
        vulnerabilities.append({
            "id": "VULN-002",
            "type": "Hardcoded Credentials",
            "severity": "🔴 CRITICAL",
            "line": [i+1 for i, l in enumerate(content.split('\n')) if re.search(r'(PASSWORD|SECRET|KEY|TOKEN)\s*=\s*["\']', l, re.IGNORECASE)],
            "description": "Sensitive credentials hardcoded in source code",
            "fix": "Use environment variables: os.environ.get('SECRET_KEY')"
        })

    # 3. Weak Hashing
    if re.search(r'hashlib\.(md5|sha1)\s*\(', content):
        vulnerabilities.append({
            "id": "VULN-003",
            "type": "Weak Cryptography",
            "severity": "🟠 HIGH",
            "line": [i+1 for i, l in enumerate(content.split('\n')) if 'md5' in l or 'sha1' in l],
            "description": "MD5/SHA1 are cryptographically broken for passwords",
            "fix": "Use bcrypt or hashlib.sha256/sha512 with salt"
        })

    # 4. Command Injection
    if re.search(r'os\.system\s*\(.*\+', content) or \
       re.search(r'os\.system\s*\(f["\']', content):
        vulnerabilities.append({
            "id": "VULN-004",
            "type": "Command Injection",
            "severity": "🔴 CRITICAL",
            "line": [i+1 for i, l in enumerate(content.split('\n')) if 'os.system' in l and ('+' in l or 'f"' in l or "f'" in l)],
            "description": "User input passed directly to system command",
            "fix": "Use subprocess with list args: subprocess.run(['ping', '-c', '1', host], shell=False)"
        })

    # 5. No Input Validation
    if re.search(r'f["\']INSERT INTO.*{', content):
        vulnerabilities.append({
            "id": "VULN-005",
            "type": "Missing Input Validation",
            "severity": "🟠 HIGH",
            "line": [i+1 for i, l in enumerate(content.split('\n')) if 'INSERT INTO' in l and '{' in l],
            "description": "No sanitization or validation of user input before DB insert",
            "fix": "Validate input length, type, and format before processing"
        })

    # Print Results
    if vulnerabilities:
        print(f"⚠️  Found {len(vulnerabilities)} vulnerabilities:\n")
        for v in vulnerabilities:
            print(f"  [{v['severity']}] {v['id']}: {v['type']}")
            print(f"  📍 Line(s): {v['line']}")
            print(f"  📝 Issue: {v['description']}")
            print(f"  ✅ Fix: {v['fix']}")
            print(f"  {'-'*55}")
    else:
        print("✅ No vulnerabilities found!")

    # Summary
    critical = sum(1 for v in vulnerabilities if 'CRITICAL' in v['severity'])
    high = sum(1 for v in vulnerabilities if 'HIGH' in v['severity'])

    print(f"\n📊 Summary:")
    print(f"  🔴 Critical : {critical}")
    print(f"  🟠 High     : {high}")
    print(f"  📁 Total    : {len(vulnerabilities)}")

    # Save Report
    with open("security_report.txt", "w") as f:
        f.write(f"Security Analysis Report\n{'='*40}\n")
        for v in vulnerabilities:
            f.write(f"\n[{v['severity']}] {v['id']}: {v['type']}\n")
            f.write(f"Line(s): {v['line']}\n")
            f.write(f"Issue: {v['description']}\n")
            f.write(f"Fix: {v['fix']}\n")

    print(f"\n✅ Report saved to security_report.txt")

analyze_file("vulnerable_app.py")
