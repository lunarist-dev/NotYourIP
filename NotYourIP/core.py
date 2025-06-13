"""
NotYourIP - Scanner Detection and Blocking Library
================================================

A Python library for detecting and blocking various types of scanners,
crawlers, and malicious IP addresses in Flask applications.

Created By Discord: lunarist._.dev

"""

import requests
import ipaddress
import json
import time
from typing import Dict, List, Optional, Set
from datetime import datetime, timedelta
import threading
import logging

class NotYourIp:
   
    def __init__(self):
        # Settings dictionary - user can modify these
        self.setting = {
            "enable_cloud_check": True,
            "enable_proxy_check": True,
            "enable_grabber_check": True,
            "cache_duration": 3600,  # 1 hour
            "log_blocked": True,
            "abuseipdb_api": "",  # AbuseIPDB API key
            "virustotal_api": "",  # VirusTotal API key
            "proxycheck_api": "",  # ProxyCheck.io API key
            "max_requests_per_minute": 30,
            "rate_limit_window": 60,
            "block_tor": True,
            "block_datacenter": True,
            "strict_mode": False  # More aggressive blocking
        }

        self._ip_cache: Dict[str, Dict] = {}
        self._cache_lock = threading.Lock()

        self.scanner_agents = [
            'nmap', 'masscan', 'zmap', 'sqlmap', 'nikto', 'dirb', 'gobuster',
            'wpscan', 'nuclei', 'httpx', 'subfinder', 'amass', 'shodan',
            'censys', 'zgrab', 'python-requests', 'curl', 'wget',
            'scanner', 'bot', 'crawler', 'spider', 'scraper', 'postman',
            'burpsuite', 'owasp', 'metasploit', 'skipfish', 'w3af', 'WanScannerBot'
        ]

        self.known_bad_ips = set()

        self.request_tracking: Dict[str, List[float]] = {}
        
        if self.setting["log_blocked"]:
            logging.basicConfig(level=logging.INFO)
            self.logger = logging.getLogger('NotYourIp')

    def _check_with_proxycheck(self, ip: str) -> Dict[str, any]:
        if not self.setting["proxycheck_api"]:
            return {}
            
        try:
            params = {
                'key': self.setting["proxycheck_api"],
                'vpn': '1',
                'asn': '1',
                'node': '1',
                'time': '1',
                'inf': '0',
                'risk': '1'
            }
            
            response = requests.get(
                f"https://proxycheck.io/v2/{ip}",
                params=params,
                timeout=3
            )
            
            if response.status_code == 200:
                data = response.json()
                if ip in data:
                    return data[ip]
        except Exception as e:
            if self.setting["log_blocked"]:
                self.logger.debug(f"ProxyCheck API error for {ip}: {e}")
        
        return {}
    
    def _get_cached_result(self, ip: str, check_type: str) -> Optional[bool]:
        with self._cache_lock:
            if ip in self._ip_cache:
                cache_entry = self._ip_cache[ip]
                if check_type in cache_entry:
                    timestamp, result = cache_entry[check_type]
                    if time.time() - timestamp < self.setting["cache_duration"]:
                        return result
            return None
    
    def _set_cached_result(self, ip: str, check_type: str, result: bool):
        with self._cache_lock:
            if ip not in self._ip_cache:
                self._ip_cache[ip] = {}
            self._ip_cache[ip][check_type] = (time.time(), result)

    def IsCloudService(self, ip: str) -> bool:
        if not self.setting["enable_cloud_check"]:
            return False

        cached = self._get_cached_result(ip, 'cloud')
        if cached is not None:
            return cached

        proxy_data = self._check_with_proxycheck(ip)
        if proxy_data:
            provider = proxy_data.get('provider', '').lower()
            ip_type = proxy_data.get('type', '').lower()
            
            cloud_providers = [
                'amazon', 'aws', 'google', 'microsoft', 'azure', 
                'digitalocean', 'vultr', 'linode', 'ovh', 'hetzner',
                'cloudflare', 'fastly', 'datacenter', 'hosting'
            ]
            
            is_cloud = (
                ip_type in ['hosting', 'datacenter'] or
                any(cloud in provider for cloud in cloud_providers)
            )
            
            self._set_cached_result(ip, 'cloud', is_cloud)
            if is_cloud and self.setting["log_blocked"]:
                self.logger.info(f"Cloud service detected: {ip} ({provider})")
            return is_cloud
        
        self._set_cached_result(ip, 'cloud', False)
        return False
    
    def IsProxy(self, ip: str) -> bool:
        if not self.setting["enable_proxy_check"]:
            return False

        cached = self._get_cached_result(ip, 'proxy')
        if cached is not None:
            return cached

        proxy_data = self._check_with_proxycheck(ip)
        if proxy_data:
            is_proxy = (
                proxy_data.get('proxy') == 'yes' or
                proxy_data.get('vpn') == 'yes' or
                proxy_data.get('tor') == 'yes'
            )

            risk_score = proxy_data.get('risk', 0)
            if risk_score >= 66: 
                is_proxy = True
            
            self._set_cached_result(ip, 'proxy', is_proxy)
            if is_proxy and self.setting["log_blocked"]:
                proxy_type = []
                if proxy_data.get('proxy') == 'yes':
                    proxy_type.append('proxy')
                if proxy_data.get('vpn') == 'yes':
                    proxy_type.append('vpn')
                if proxy_data.get('tor') == 'yes':
                    proxy_type.append('tor')
                
                self.logger.info(f"Proxy/VPN detected: {ip} ({'/'.join(proxy_type)}, risk: {risk_score})")
            return is_proxy

        if self.setting["abuseipdb_api"]:
            try:
                headers = {
                    'Key': self.setting["abuseipdb_api"],
                    'Accept': 'application/json'
                }
                params = {'ipAddress': ip, 'maxAgeInDays': 90, 'verbose': ''}
                response = requests.get(
                    'https://api.abuseipdb.com/api/v2/check',
                    headers=headers, params=params, timeout=3
                )
                if response.status_code == 200:
                    data = response.json()
                    abuse_confidence = data.get('data', {}).get('abuseConfidencePercentage', 0)
                    if abuse_confidence > 50:
                        self._set_cached_result(ip, 'proxy', True)
                        if self.setting["log_blocked"]:
                            self.logger.warning(f"Malicious IP detected via AbuseIPDB: {ip} (confidence: {abuse_confidence}%)")
                        return True
            except Exception as e:
                if self.setting["log_blocked"]:
                    self.logger.debug(f"AbuseIPDB API error for {ip}: {e}")
        
        self._set_cached_result(ip, 'proxy', False)
        return False
    
    def IsGrabberIP(self, ip: str, user_agent: str = "") -> bool:
        if not self.setting["enable_grabber_check"]:
            return False

        cached = self._get_cached_result(ip, 'grabber')
        if cached is not None:
            return cached

        if ip in self.known_bad_ips:
            self._set_cached_result(ip, 'grabber', True)
            if self.setting["log_blocked"]:
                self.logger.warning(f"Known malicious IP blocked: {ip}")
            return True

        if user_agent:
            user_agent_lower = user_agent.lower()
            for pattern in self.scanner_agents:
                if pattern in user_agent_lower:
                    self._set_cached_result(ip, 'grabber', True)
                    if self.setting["log_blocked"]:
                        self.logger.warning(f"Scanner user agent detected: {ip} - {user_agent}")
                    return True
        
        current_time = time.time()
        if ip not in self.request_tracking:
            self.request_tracking[ip] = []

        self.request_tracking[ip] = [
            req_time for req_time in self.request_tracking[ip]
            if current_time - req_time < self.setting["rate_limit_window"]
        ]

        self.request_tracking[ip].append(current_time)

        if len(self.request_tracking[ip]) > self.setting["max_requests_per_minute"]:
            self._set_cached_result(ip, 'grabber', True)
            if self.setting["log_blocked"]:
                self.logger.warning(f"Rate limit exceeded: {ip} ({len(self.request_tracking[ip])} requests)")
            return True
        
        self._set_cached_result(ip, 'grabber', False)
        return False
    
    def IsBlocked(self, ip: str, user_agent: str = "") -> Dict[str, bool]:
        results = {
            'cloud': self.IsCloudService(ip),
            'proxy': self.IsProxy(ip), 
            'grabber': self.IsGrabberIP(ip, user_agent),
            'blocked': False
        }

        results['blocked'] = any([
            results['cloud'],
            results['proxy'], 
            results['grabber']
        ])
        
        return results
    
    def AddBadIP(self, ip: str):
        self.known_bad_ips.add(ip)
        with self._cache_lock:
            if ip in self._ip_cache:
                del self._ip_cache[ip]
    
    def RemoveBadIP(self, ip: str):
        self.known_bad_ips.discard(ip)
        with self._cache_lock:
            if ip in self._ip_cache:
                del self._ip_cache[ip]
    
    def ClearCache(self):
        with self._cache_lock:
            self._ip_cache.clear()
        self.request_tracking.clear()
    
    def GetStats(self) -> Dict:
        return {
            'cached_ips': len(self._ip_cache),
            'tracked_ips': len(self.request_tracking),
            'known_bad_ips': len(self.known_bad_ips),
            'settings': self.setting
        }

