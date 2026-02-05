# ProcessScope

ProcessScope is a lightweight Windows process inspection toolkit for security research and incident response. It analyzes running processes, modules, threads, and memory regions to identify potentially malicious behavior.

## Purpose

This tool is designed for defensive security research:

- Analyze process behavior for security investigations
- Identify suspicious process characteristics
- Support incident response activities
- Educational purposes for Windows internals

**This tool does NOT include injection, stealth, or bypass capabilities.** It performs read-only analysis and respects Windows security boundaries.

## Interface

ProcessScope is a **command-line tool** designed for automation and scripting. There is no GUI to keep the tool lightweight and portable.

## Features

- **Process Enumeration**: List running processes with detailed information
- **Module Analysis**: Enumerate loaded modules with digital signature verification
- **Thread Inspection**: Analyze threads and detect anomalous start addresses
- **Memory Region Scanning**: Walk virtual memory and flag suspicious protections
- **Risk Scoring**: Calculate risk scores based on heuristics
- **JSON Export**: Export detailed reports in JSON format

## Requirements

- Windows 7 or later
- Visual Studio 2019+ (C++17) or CMake 3.16+
- Administrative privileges (recommended for full functionality)

## Building

### Using Visual Studio (Recommended)

1. Open `ProcessScope.sln` in Visual Studio 2019 or later
2. Select **Release/x64** configuration
3. Build Solution (press **F7**)
4. Executable: `bin\x64\Release\ProcessScope.exe`

### Using CMake

If you have CMake installed:
```cmd
mkdir build
cd build
cmake ..
cmake --build . --config Release
```

## Usage

### Basic Commands

```cmd
# List all running processes
ProcessScope.exe --list

# Scan a specific process
ProcessScope.exe --scan <pid>

# Scan all accessible processes
ProcessScope.exe --scan-all
```

### Examples

```cmd
# List processes
ProcessScope.exe --list

# Scan notepad.exe (assuming PID 1234)
ProcessScope.exe --scan 1234

# Scan all processes and export reports
ProcessScope.exe --scan-all
```

## Output

### Console Output
The tool provides formatted console output with sections:
- Process information (PID, PPID, name, path, architecture, session)
- Module details (name, base address, size, signature status)
- Thread analysis (TID, start address, anomalous detection)
- Memory summary (total regions, suspicious regions)
- Risk assessment (score, level, details)

### JSON Export
Each scan generates a JSON report in `./reports/` with filename format: `<pid>_<timestamp>.json`

#### Sample JSON Schema
```json
{
  "tool_info": {
    "name": "ProcessScope",
    "version": "1.0.0",
    "timestamp": "20240205_143022_123"
  },
  "host_info": {
    "computer_name": "DESKTOP-ABC123",
    "username": "user"
  },
  "process": {
    "pid": 1234,
    "ppid": 567,
    "name": "notepad.exe",
    "full_path": "C:\\Windows\\System32\\notepad.exe",
    "architecture": "x64",
    "session_id": 1
  },
  "modules": [
    {
      "name": "notepad.exe",
      "full_path": "C:\\Windows\\System32\\notepad.exe",
      "base_address": "0x7ff6c8a00000",
      "size": 249856,
      "signed": true,
      "signer_name": "Microsoft Windows"
    }
  ],
  "threads": [
    {
      "tid": 1236,
      "start_address": "0x7ff6c8a1234",
      "anomalous_start": false
    }
  ],
  "memory_regions": [
    {
      "base_address": "0x7ff6c8a00000",
      "size": 65536,
      "state": "COMMIT",
      "type": "IMAGE",
      "protection": "RX",
      "is_executable": true,
      "is_writable": false,
      "is_suspicious": false
    }
  ],
  "risk_assessment": {
    "score": 0,
    "level": "Low",
    "details": "No risk factors detected"
  }
}
```

## Risk Scoring Heuristics

ProcessScope calculates risk scores using these rules:

| Risk Factor | Score | Description |
|-------------|--------|-------------|
| RWX Memory Region | +3 | Memory with Read+Write+Execute permissions |
| Executable Private Region | +1 | Executable memory >1MB not backed by file |
| Anomalous Thread Start | +2 | Thread start address outside any loaded module |
| Unsigned Module | +1 | Module without valid digital signature (max +3) |

### Risk Levels
- **Low (0-2)**: Minimal suspicious indicators
- **Medium (3-5)**: Some suspicious characteristics present
- **High (6+)**: Multiple high-risk indicators detected

The heuristics exclude unsigned modules from trusted locations (Windows\System32, Program Files, etc.) to reduce false positives.

## Limitations

- Requires appropriate privileges to access certain processes
- Signature verification may fail for files with permission issues
- Thread start address detection uses best-effort approach
- Memory scanning limited to committed regions for performance
- Some advanced evasion techniques may not be detected

## Security Considerations

- Tool requires read-only access to target processes
- No code injection or modification capabilities
- Respects Windows security boundaries
- All operations logged locally
- No network communications

## Troubleshooting

### Access Denied Errors
Run as Administrator for full functionality. Some system processes may remain inaccessible due to protection mechanisms.

### Signature Verification Failures
Ensure target files are accessible and not locked by other processes.

### Build Issues
- Ensure all required Windows SDK components are installed
- Verify C++17 support in your compiler
- Check that all required libraries are available


