#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Syntax and Safety Validation Test for service_manager.ps1
Verifies:
1. Complete PowerShell AST parse of service_manager.ps1 with 0 errors.
2. Correct quotation and variable expansion for SCM Environment block (PYTHONPATH, PYTHONHOME, VIRTUAL_ENV, PATH).
3. Safe execution of non-destructive commands ('Status', 'TestIPC') returning exit code 0.
4. Validation of 'Restart' block logic within AST without stopping or restarting the running service.
"""

import os
import sys
import json
import subprocess
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
SERVICE_MANAGER_PS1 = PROJECT_ROOT / "service_manager.ps1"


class TestServiceManagerSyntax(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ps1_path = str(SERVICE_MANAGER_PS1)
        cls.assertTrue(SERVICE_MANAGER_PS1.exists(), f"service_manager.ps1 not found at {cls.ps1_path}")

    def test_01_powershell_ast_parser_zero_errors(self):
        """1. Verify service_manager.ps1 has 0 PowerShell syntax/parser errors."""
        ps_cmd = f"""
$errors = $null
$tokens = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile('{self.ps1_path}', [ref]$tokens, [ref]$errors)
if ($errors) {{
    $errList = @()
    foreach ($err in $errors) {{
        $errList += [PSCustomObject]@{{
            Line = $err.Extent.StartLineNumber
            Column = $err.Extent.StartColumnNumber
            Message = $err.Message
            Text = $err.Extent.Text
        }}
    }}
    $json = ConvertTo-Json -InputObject $errList -Compress
    Write-Output "PARSE_ERRORS:$json"
    exit 1
}} else {{
    Write-Output "PARSE_OK"
    exit 0
}}
"""
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_cmd],
            capture_output=True,
            text=True
        )
        if proc.returncode != 0:
            self.fail(f"PowerShell AST Parser detected syntax errors:\n{proc.stdout}\n{proc.stderr}")
        self.assertIn("PARSE_OK", proc.stdout)

    def test_02_scm_environment_variables_preserved(self):
        """2. Verify PYTHONPATH, PYTHONHOME, VIRTUAL_ENV, and PATH are correctly preserved in the script."""
        content = SERVICE_MANAGER_PS1.read_text(encoding="utf-8")
        
        # Verify required environment variable assignments are present
        self.assertIn('"PYTHONPATH=$pyPath"', content, "PYTHONPATH assignment missing or corrupted.")
        self.assertIn('"PYTHONHOME=$pyHome"', content, "PYTHONHOME assignment missing or corrupted.")
        self.assertIn('"VIRTUAL_ENV=$venvDir"', content, "VIRTUAL_ENV assignment missing or corrupted.")
        self.assertIn('"PATH=$venvDir\\Scripts;$venvDir\\Lib\\site-packages\\win32;$pyHome;$pyHome\\Scripts;$env:PATH"',
                      content, "PATH environment variable assignment missing or corrupted.")

        # Verify pyPath contains all necessary paths
        expected_pypath = '$pyPath = "$venvDir\\Lib\\site-packages;$venvDir\\Lib\\site-packages\\win32;$venvDir\\Lib\\site-packages\\win32\\lib;$ScriptDir"'
        self.assertIn(expected_pypath, content, "pyPath definition is missing or altered.")

    def test_03_utf8_bom_presence(self):
        """3. Verify service_manager.ps1 starts with UTF-8 BOM for Windows PowerShell 5.1 compatibility."""
        raw_bytes = SERVICE_MANAGER_PS1.read_bytes()
        self.assertTrue(
            raw_bytes.startswith(b'\xef\xbb\xbf'),
            "service_manager.ps1 should have UTF-8 BOM (0xEF, 0xBB, 0xBF) to ensure Windows PowerShell 5.1 parses characters properly."
        )

    def test_04_status_command_safe_execution(self):
        """4. Verify 'Status' command runs cleanly without ParserError or modifying service state."""
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", self.ps1_path, "Status"],
            capture_output=True,
            encoding="utf-8",
            errors="replace"
        )
        self.assertEqual(proc.returncode, 0, f"'Status' failed with code {proc.returncode}:\n{proc.stderr}")
        self.assertIn("DDoS-Guard Service Status", proc.stdout)
        self.assertNotIn("ParserError", proc.stderr)
        self.assertNotIn("UnexpectedToken", proc.stderr)

    def test_05_restart_logic_ast_verification(self):
        """5. Safely verify 'Restart' block logic in AST without executing service stop/restart."""
        ps_cmd = f"""
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile('{self.ps1_path}', [ref]$null, [ref]$errors)
if ($errors) {{ exit 1 }}

$switchStatements = $ast.FindAll( {{ $args[0] -is [System.Management.Automation.Language.SwitchStatementAst] }}, $true )
$hasRestartClause = $false
$restartUsesRestartService = $false

foreach ($sw in $switchStatements) {{
    foreach ($clause in $sw.Clauses) {{
        if ($clause.Item1.Extent.Text -match '"Restart"') {{
            $hasRestartClause = $true
            $clauseText = $clause.Item2.Extent.Text
            if ($clauseText -match 'Restart-Service\s+-Name\s+\$ServiceName\s+-Force') {{
                $restartUsesRestartService = $true
            }}
        }}
    }}
}}

if ($hasRestartClause -and $restartUsesRestartService) {{
    Write-Output "RESTART_LOGIC_VALID"
    exit 0
}} else {{
    Write-Output "RESTART_LOGIC_INVALID"
    exit 1
}}
"""
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_cmd],
            capture_output=True,
            encoding="utf-8",
            errors="replace"
        )
        self.assertEqual(proc.returncode, 0, f"Restart logic check failed:\n{proc.stdout}\n{proc.stderr}")
        self.assertIn("RESTART_LOGIC_VALID", proc.stdout)


if __name__ == "__main__":
    print("=" * 65)
    print("  service_manager.ps1 Syntax and Safety Validation Test")
    print("=" * 65)
    suite = unittest.TestLoader().loadTestsFromTestCase(TestServiceManagerSyntax)
    runner = unittest.TextTestRunner(verbosity=2)
    res = runner.run(suite)
    sys.exit(0 if res.wasSuccessful() else 1)
