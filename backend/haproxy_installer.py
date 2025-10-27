#!/usr/bin/env python3
"""
HAProxy Automatic Installer and Cluster Manager
Handles remote HAProxy installation and cluster configuration via SSH
"""

import asyncio
import json
import logging
import paramiko
import tempfile
from typing import Dict, List, Optional, Tuple
from pathlib import Path

logger = logging.getLogger(__name__)

class HAProxyInstaller:
    """Handles HAProxy installation and cluster configuration"""
    
    def __init__(self, host: str, ssh_username: str, ssh_password: Optional[str] = None, 
                 ssh_key_content: Optional[str] = None, ssh_private_key_path: Optional[str] = None):
        self.host = host
        self.ssh_username = ssh_username
        self.ssh_password = ssh_password
        self.ssh_key_content = ssh_key_content
        self.ssh_private_key_path = ssh_private_key_path
        self.ssh_client = None
        
    async def connect_ssh(self) -> bool:
        """Establish SSH connection to the target server"""
        try:
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Determine authentication method
            if self.ssh_key_content:
                # Use SSH key from content
                key_file = tempfile.NamedTemporaryFile(mode='w', delete=False)
                key_file.write(self.ssh_key_content)
                key_file.close()
                key = paramiko.RSAKey.from_private_key_file(key_file.name)
                self.ssh_client.connect(
                    hostname=self.host,
                    username=self.ssh_username,
                    pkey=key,
                    timeout=30
                )
                Path(key_file.name).unlink()  # Clean up temp file
                
            elif self.ssh_private_key_path:
                # Use SSH key from file path
                key = paramiko.RSAKey.from_private_key_file(self.ssh_private_key_path)
                self.ssh_client.connect(
                    hostname=self.host,
                    username=self.ssh_username,
                    pkey=key,
                    timeout=30
                )
                
            elif self.ssh_password:
                # Use password authentication
                self.ssh_client.connect(
                    hostname=self.host,
                    username=self.ssh_username,
                    password=self.ssh_password,
                    timeout=30
                )
                
            else:
                logger.error("No SSH authentication method provided")
                return False
                
            logger.info(f"SSH connection established to {self.host}")
            return True
            
        except Exception as e:
            logger.error(f"SSH connection failed to {self.host}: {e}")
            return False
    
    async def execute_command(self, command: str) -> Tuple[int, str, str]:
        """Execute command via SSH and return exit code, stdout, stderr"""
        if not self.ssh_client:
            raise Exception("SSH connection not established")
            
        try:
            stdin, stdout, stderr = self.ssh_client.exec_command(command)
            exit_code = stdout.channel.recv_exit_status()
            stdout_content = stdout.read().decode('utf-8')
            stderr_content = stderr.read().decode('utf-8')
            
            logger.debug(f"Command: {command}")
            logger.debug(f"Exit code: {exit_code}")
            logger.debug(f"Stdout: {stdout_content}")
            if stderr_content:
                logger.debug(f"Stderr: {stderr_content}")
                
            return exit_code, stdout_content, stderr_content
            
        except Exception as e:
            logger.error(f"Command execution failed: {e}")
            return -1, "", str(e)
    
    async def detect_os(self) -> str:
        """Detect operating system of the target server"""
        commands = [
            ("cat /etc/os-release", "linux"),
            ("uname -s", "unix")
        ]
        
        for cmd, os_type in commands:
            exit_code, stdout, stderr = await self.execute_command(cmd)
            if exit_code == 0 and stdout:
                if "ubuntu" in stdout.lower():
                    return "ubuntu"
                elif "debian" in stdout.lower():
                    return "debian" 
                elif "centos" in stdout.lower() or "rhel" in stdout.lower():
                    return "centos"
                elif "fedora" in stdout.lower():
                    return "fedora"
                else:
                    return "linux"
        
        return "unknown"
    
    async def install_haproxy(self, install_path: str = "/etc/haproxy", 
                            service_user: str = "haproxy") -> Dict[str, any]:
        """Install HAProxy on the target server"""
        result = {
            "success": False,
            "message": "",
            "haproxy_version": None,
            "installed_files": []
        }
        
        try:
            # Detect OS
            os_type = await self.detect_os()
            logger.info(f"Detected OS: {os_type}")
            
            # Install HAProxy based on OS
            if os_type in ["ubuntu", "debian"]:
                await self.install_haproxy_debian(install_path, service_user, result)
            elif os_type in ["centos", "fedora"]:
                await self.install_haproxy_rhel(install_path, service_user, result)
            else:
                result["message"] = f"Unsupported OS: {os_type}"
                return result
                
            # Verify installation
            exit_code, stdout, stderr = await self.execute_command("haproxy -v")
            if exit_code == 0 and "haproxy" in stdout.lower():
                version_line = stdout.split('\n')[0]
                result["haproxy_version"] = version_line.split()[2] if len(version_line.split()) > 2 else "unknown"
                result["success"] = True
                result["message"] = f"HAProxy installed successfully. Version: {result['haproxy_version']}"
                logger.info(result["message"])
            else:
                result["message"] = "HAProxy installation verification failed"
                
        except Exception as e:
            result["message"] = f"HAProxy installation failed: {str(e)}"
            logger.error(result["message"])
            
        return result
    
    async def install_haproxy_debian(self, install_path: str, service_user: str, result: Dict):
        """Install HAProxy on Debian/Ubuntu systems"""
        commands = [
            "apt-get update",
            "apt-get install -y haproxy keepalived",
            f"systemctl enable haproxy",
            f"systemctl enable keepalived",
            f"mkdir -p {install_path}",
            f"mkdir -p /run/haproxy",
            f"chown -R {service_user}:{service_user} /run/haproxy"
        ]
        
        for cmd in commands:
            exit_code, stdout, stderr = await self.execute_command(f"sudo {cmd}")
            if exit_code != 0:
                raise Exception(f"Command failed: {cmd} - {stderr}")
                
        result["installed_files"].extend([
            f"{install_path}/haproxy.cfg",
            "/etc/keepalived/keepalived.conf",
            "/etc/systemd/system/haproxy.service",
            "/etc/systemd/system/keepalived.service"
        ])
    
    async def install_haproxy_rhel(self, install_path: str, service_user: str, result: Dict):
        """Install HAProxy on CentOS/RHEL/Fedora systems"""
        commands = [
            "yum update -y",
            "yum install -y haproxy keepalived",
            f"systemctl enable haproxy",
            f"systemctl enable keepalived",
            f"mkdir -p {install_path}",
            f"mkdir -p /run/haproxy", 
            f"chown -R {service_user}:{service_user} /run/haproxy"
        ]
        
        for cmd in commands:
            exit_code, stdout, stderr = await self.execute_command(f"sudo {cmd}")
            if exit_code != 0:
                raise Exception(f"Command failed: {cmd} - {stderr}")
                
        result["installed_files"].extend([
            f"{install_path}/haproxy.cfg",
            "/etc/keepalived/keepalived.conf",
            "/etc/systemd/system/haproxy.service",
            "/etc/systemd/system/keepalived.service"
        ])
    
    async def configure_haproxy_cluster(self, cluster_config: Dict) -> Dict[str, any]:
        """Configure HAProxy for cluster mode with keepalived"""
        result = {
            "success": False,
            "message": "",
            "config_files": []
        }
        
        try:
            install_path = cluster_config.get("install_path", "/etc/haproxy")
            keepalive_ip = cluster_config["keepalive_ip"]
            cluster_nodes = cluster_config.get("cluster_nodes", [])
            cluster_priority = cluster_config.get("cluster_priority", 100)
            stats_socket_path = cluster_config.get("stats_socket_path", "/run/haproxy/admin.sock")
            
            # Generate HAProxy configuration
            haproxy_config = self.generate_haproxy_config(keepalive_ip, stats_socket_path)
            
            # Generate Keepalived configuration
            keepalived_config = self.generate_keepalived_config(
                keepalive_ip, self.host, cluster_nodes, cluster_priority
            )
            
            # Upload HAProxy configuration
            haproxy_config_path = f"{install_path}/haproxy.cfg"
            await self.upload_file_content(haproxy_config, haproxy_config_path)
            result["config_files"].append(haproxy_config_path)
            
            # Upload Keepalived configuration 
            keepalived_config_path = "/etc/keepalived/keepalived.conf"
            await self.upload_file_content(keepalived_config, keepalived_config_path)
            result["config_files"].append(keepalived_config_path)
            
            # Restart services
            restart_commands = [
                "sudo systemctl restart haproxy",
                "sudo systemctl restart keepalived",
                "sudo systemctl status haproxy --no-pager",
                "sudo systemctl status keepalived --no-pager"
            ]
            
            for cmd in restart_commands:
                exit_code, stdout, stderr = await self.execute_command(cmd)
                if "systemctl restart" in cmd and exit_code != 0:
                    raise Exception(f"Service restart failed: {cmd} - {stderr}")
            
            result["success"] = True
            result["message"] = f"HAProxy cluster configured successfully with keepalive IP {keepalive_ip}"
            
        except Exception as e:
            result["message"] = f"HAProxy cluster configuration failed: {str(e)}"
            logger.error(result["message"])
            
        return result
    
    def generate_haproxy_config(self, keepalive_ip: str, stats_socket_path: str) -> str:
        """Generate HAProxy configuration for cluster mode"""
        config = f"""#---------------------------------------------------------------------
# HAProxy Configuration - Cluster Mode
# Generated automatically by HAProxy OpenManager
#---------------------------------------------------------------------

global
    daemon
    user haproxy
    group haproxy
    log stdout local0
    
    # Stats socket for management
    stats socket {stats_socket_path} mode 660 level admin
    stats timeout 30s
    
    # SSL/TLS configuration
    ssl-default-bind-ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384
    ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets

defaults
    mode http
    log global
    option httplog
    option dontlognull
    option log-health-checks
    option forwardfor except 127.0.0.0/8
    option redispatch
    
    timeout connect 5000
    timeout client 50000
    timeout server 50000
    
    # Error pages
    errorfile 400 /etc/haproxy/errors/400.http
    errorfile 403 /etc/haproxy/errors/403.http
    errorfile 408 /etc/haproxy/errors/408.http
    errorfile 500 /etc/haproxy/errors/500.http
    errorfile 502 /etc/haproxy/errors/502.http
    errorfile 503 /etc/haproxy/errors/503.http
    errorfile 504 /etc/haproxy/errors/504.http

#---------------------------------------------------------------------
# Frontend Configuration
#---------------------------------------------------------------------
frontend main_frontend
    bind {keepalive_ip}:80
    bind {keepalive_ip}:443 ssl crt /etc/ssl/certs/haproxy.pem
    
    # Redirect HTTP to HTTPS
    redirect scheme https if !{{ ssl_fc }}
    
    # Default backend
    default_backend main_backend

#---------------------------------------------------------------------
# Backend Configuration
#---------------------------------------------------------------------
backend main_backend
    balance roundrobin
    option httpchk GET /health
    
    # Add your backend servers here
    # server web1 192.168.1.10:80 check
    # server web2 192.168.1.11:80 check

#---------------------------------------------------------------------
# Stats Interface
#---------------------------------------------------------------------
frontend stats
    bind {keepalive_ip}:8404
    stats enable
    stats uri /stats
    stats refresh 30s
    stats admin if TRUE
    stats show-legends
    stats show-node

"""
        return config
    
    def generate_keepalived_config(self, keepalive_ip: str, current_host: str, 
                                 cluster_nodes: List[str], priority: int) -> str:
        """Generate Keepalived configuration for HA setup"""
        
        # Determine state based on priority (highest priority is MASTER)
        all_nodes = [current_host] + cluster_nodes
        all_priorities = [priority] + [priority - 10 * (i + 1) for i in range(len(cluster_nodes))]
        max_priority = max(all_priorities)
        state = "MASTER" if priority == max_priority else "BACKUP"
        
        config = f"""#---------------------------------------------------------------------
# Keepalived Configuration - HAProxy Cluster
# Generated automatically by HAProxy OpenManager
#---------------------------------------------------------------------

global_defs {{
    router_id HAProxy_Cluster_{current_host.replace('.', '_')}
    enable_script_security
    script_user haproxy
}}

# Health check script for HAProxy
vrrp_script haproxy_check {{
    script "/bin/curl -f http://localhost:8404/stats || exit 1"
    interval 2
    weight -2
    fall 3
    rise 2
}}

# VRRP instance for keepalive IP
vrrp_instance VI_HAProxy {{
    state {state}
    interface eth0
    virtual_router_id 51
    priority {priority}
    advert_int 1
    
    authentication {{
        auth_type PASS
        auth_pass haproxy_cluster
    }}
    
    virtual_ipaddress {{
        {keepalive_ip}/24
    }}
    
    track_script {{
        haproxy_check
    }}
    
    notify_master "/bin/echo 'Became MASTER' | logger -t keepalived"
    notify_backup "/bin/echo 'Became BACKUP' | logger -t keepalived"
    notify_fault "/bin/echo 'Fault detected' | logger -t keepalived"
}}

"""
        return config
    
    async def upload_file_content(self, content: str, remote_path: str):
        """Upload file content to remote server via SSH"""
        if not self.ssh_client:
            raise Exception("SSH connection not established")
            
        try:
            # Create temporary file with content
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
                temp_file.write(content)
                temp_file_path = temp_file.name
            
            # Upload file via SFTP
            sftp = self.ssh_client.open_sftp()
            sftp.put(temp_file_path, remote_path)
            sftp.close()
            
            # Set proper permissions
            await self.execute_command(f"sudo chmod 644 {remote_path}")
            
            # Clean up temp file
            Path(temp_file_path).unlink()
            
            logger.info(f"File uploaded successfully: {remote_path}")
            
        except Exception as e:
            logger.error(f"File upload failed: {e}")
            raise
    
    async def uninstall_haproxy(self) -> Dict[str, any]:
        """Uninstall HAProxy from the target server"""
        result = {
            "success": False,
            "message": "",
            "uninstalled_files": []
        }
        
        try:
            # Detect OS
            os_type = await self.detect_os()
            logger.info(f"Detected OS for uninstall: {os_type}")
            
            # Stop services first
            stop_commands = [
                "sudo systemctl stop haproxy || true",
                "sudo systemctl stop keepalived || true"
            ]
            
            for cmd in stop_commands:
                exit_code, stdout, stderr = await self.execute_command(cmd)
                logger.debug(f"Stop command: {cmd}, exit_code: {exit_code}")
            
            # Disable services
            disable_commands = [
                "sudo systemctl disable haproxy || true",
                "sudo systemctl disable keepalived || true"
            ]
            
            for cmd in disable_commands:
                exit_code, stdout, stderr = await self.execute_command(cmd)
                logger.debug(f"Disable command: {cmd}, exit_code: {exit_code}")
            
            # Uninstall packages based on OS
            if os_type in ["ubuntu", "debian"]:
                await self.uninstall_haproxy_debian(result)
            elif os_type in ["centos", "fedora"]:
                await self.uninstall_haproxy_rhel(result)
            else:
                result["message"] = f"Unsupported OS for uninstall: {os_type}"
                return result
            
            # Clean up configuration directories
            cleanup_commands = [
                "sudo rm -rf /etc/haproxy",
                "sudo rm -rf /etc/keepalived", 
                "sudo rm -rf /run/haproxy",
                "sudo rm -rf /var/lib/haproxy",
                "sudo rm -rf /var/log/haproxy"
            ]
            
            cleaned_paths = []
            for cmd in cleanup_commands:
                exit_code, stdout, stderr = await self.execute_command(cmd)
                if exit_code == 0:
                    path = cmd.split()[-1]  # Extract path from rm command
                    cleaned_paths.append(path)
            
            result["uninstalled_files"].extend(cleaned_paths)
            result["success"] = True
            result["message"] = "HAProxy uninstalled successfully"
            logger.info(result["message"])
                
        except Exception as e:
            result["message"] = f"HAProxy uninstall failed: {str(e)}"
            logger.error(result["message"])
            
        return result
    
    async def uninstall_haproxy_debian(self, result: Dict):
        """Uninstall HAProxy on Debian/Ubuntu systems"""
        commands = [
            "sudo apt-get remove -y haproxy keepalived",
            "sudo apt-get purge -y haproxy keepalived",
            "sudo apt-get autoremove -y"
        ]
        
        for cmd in commands:
            exit_code, stdout, stderr = await self.execute_command(cmd)
            if exit_code != 0:
                logger.warning(f"Uninstall command had issues: {cmd} - {stderr}")
                # Don't fail completely for package removal issues
                
        result["uninstalled_files"].extend([
            "haproxy package",
            "keepalived package"
        ])
    
    async def uninstall_haproxy_rhel(self, result: Dict):
        """Uninstall HAProxy on CentOS/RHEL/Fedora systems"""
        commands = [
            "sudo yum remove -y haproxy keepalived",
            "sudo yum autoremove -y"
        ]
        
        for cmd in commands:
            exit_code, stdout, stderr = await self.execute_command(cmd)
            if exit_code != 0:
                logger.warning(f"Uninstall command had issues: {cmd} - {stderr}")
                # Don't fail completely for package removal issues
                
        result["uninstalled_files"].extend([
            "haproxy package", 
            "keepalived package"
        ])
    
    def close_connection(self):
        """Close SSH connection"""
        if self.ssh_client:
            self.ssh_client.close()
            self.ssh_client = None
            logger.info(f"SSH connection closed to {self.host}")


class HAProxyClusterManager:
    """Manages HAProxy cluster installation and configuration"""
    
    @staticmethod
    async def install_cluster(cluster_config: Dict) -> Dict[str, any]:
        """Install HAProxy cluster on multiple nodes"""
        result = {
            "success": False,
            "message": "",
            "node_results": {},
            "cluster_ready": False
        }
        
        try:
            main_host = cluster_config["host"]
            cluster_nodes = cluster_config.get("cluster_nodes", [])
            all_hosts = [main_host] + cluster_nodes
            
            logger.info(f"Starting HAProxy cluster installation on {len(all_hosts)} nodes")
            
            # Install HAProxy on all nodes in parallel
            installation_tasks = []
            for i, host in enumerate(all_hosts):
                installer = HAProxyInstaller(
                    host=host,
                    ssh_username=cluster_config["ssh_username"],
                    ssh_password=cluster_config.get("ssh_password"),
                    ssh_key_content=cluster_config.get("ssh_key_content"),
                    ssh_private_key_path=cluster_config.get("ssh_private_key_path")
                )
                
                task = HAProxyClusterManager.install_single_node(
                    installer, cluster_config, i == 0  # First node is primary
                )
                installation_tasks.append((host, task))
            
            # Wait for all installations to complete
            node_success_count = 0
            for host, task in installation_tasks:
                node_result = await task
                result["node_results"][host] = node_result
                if node_result["success"]:
                    node_success_count += 1
            
            # Check if cluster is ready
            if node_success_count == len(all_hosts):
                result["success"] = True
                result["cluster_ready"] = True
                result["message"] = f"HAProxy cluster installed successfully on {node_success_count}/{len(all_hosts)} nodes"
            elif node_success_count > 0:
                result["success"] = False
                result["cluster_ready"] = False
                result["message"] = f"Partial success: {node_success_count}/{len(all_hosts)} nodes installed successfully"
            else:
                result["success"] = False
                result["cluster_ready"] = False
                result["message"] = "HAProxy cluster installation failed on all nodes"
                
        except Exception as e:
            result["message"] = f"HAProxy cluster installation failed: {str(e)}"
            logger.error(result["message"])
            
        return result
    
    @staticmethod
    async def install_single_node(installer: HAProxyInstaller, cluster_config: Dict, 
                                is_primary: bool = False) -> Dict[str, any]:
        """Install HAProxy on a single node"""
        result = {
            "success": False,
            "message": "",
            "host": installer.host,
            "is_primary": is_primary,
            "installation_result": None,
            "configuration_result": None
        }
        
        try:
            # Connect via SSH
            if not await installer.connect_ssh():
                result["message"] = f"SSH connection failed to {installer.host}"
                return result
            
            # Install HAProxy
            installation_result = await installer.install_haproxy(
                install_path=cluster_config.get("install_path", "/etc/haproxy"),
                service_user=cluster_config.get("service_user", "haproxy")
            )
            result["installation_result"] = installation_result
            
            if not installation_result["success"]:
                result["message"] = f"HAProxy installation failed: {installation_result['message']}"
                return result
            
            # Configure cluster if deployment type is cluster
            if cluster_config.get("deployment_type") == "cluster":
                # Adjust priority for non-primary nodes
                config_copy = cluster_config.copy()
                if not is_primary:
                    config_copy["cluster_priority"] = cluster_config.get("cluster_priority", 100) - 10
                
                configuration_result = await installer.configure_haproxy_cluster(config_copy)
                result["configuration_result"] = configuration_result
                
                if not configuration_result["success"]:
                    result["message"] = f"HAProxy cluster configuration failed: {configuration_result['message']}"
                    return result
            
            result["success"] = True
            result["message"] = f"HAProxy installed and configured successfully on {installer.host}"
            
        except Exception as e:
            result["message"] = f"HAProxy installation failed on {installer.host}: {str(e)}"
            logger.error(result["message"])
            
        finally:
            installer.close_connection()
            
        return result 

    @staticmethod
    async def uninstall_cluster(cluster_config: Dict) -> Dict[str, any]:
        """Uninstall HAProxy cluster from multiple nodes"""
        result = {
            "success": False,
            "message": "",
            "node_results": {},
            "cluster_cleaned": False
        }
        
        try:
            main_host = cluster_config["host"]
            cluster_nodes = cluster_config.get("cluster_nodes", [])
            all_hosts = [main_host] + cluster_nodes
            
            logger.info(f"Starting HAProxy cluster uninstall on {len(all_hosts)} nodes")
            
            # Uninstall HAProxy from all nodes in parallel
            uninstall_tasks = []
            for i, host in enumerate(all_hosts):
                installer = HAProxyInstaller(
                    host=host,
                    ssh_username=cluster_config["ssh_username"],
                    ssh_password=cluster_config.get("ssh_password"),
                    ssh_key_content=cluster_config.get("ssh_key_content"),
                    ssh_private_key_path=cluster_config.get("ssh_private_key_path")
                )
                
                task = HAProxyClusterManager.uninstall_single_node(
                    installer, cluster_config, i == 0  # First node is primary
                )
                uninstall_tasks.append((host, task))
            
            # Wait for all uninstalls to complete
            node_success_count = 0
            for host, task in uninstall_tasks:
                node_result = await task
                result["node_results"][host] = node_result
                if node_result["success"]:
                    node_success_count += 1
            
            # Check if cluster is cleaned
            if node_success_count == len(all_hosts):
                result["success"] = True
                result["cluster_cleaned"] = True
                result["message"] = f"HAProxy cluster uninstalled successfully from {node_success_count}/{len(all_hosts)} nodes"
            elif node_success_count > 0:
                result["success"] = False
                result["cluster_cleaned"] = False
                result["message"] = f"Partial uninstall: {node_success_count}/{len(all_hosts)} nodes cleaned successfully"
            else:
                result["success"] = False
                result["cluster_cleaned"] = False
                result["message"] = "HAProxy cluster uninstall failed on all nodes"
                
        except Exception as e:
            result["message"] = f"HAProxy cluster uninstall failed: {str(e)}"
            logger.error(result["message"])
            
        return result
    
    @staticmethod
    async def uninstall_single_node(installer: HAProxyInstaller, cluster_config: Dict, 
                                  is_primary: bool = False) -> Dict[str, any]:
        """Uninstall HAProxy from a single node"""
        result = {
            "success": False,
            "message": "",
            "host": installer.host,
            "is_primary": is_primary,
            "uninstall_result": None
        }
        
        try:
            # Connect via SSH
            if not await installer.connect_ssh():
                result["message"] = f"SSH connection failed to {installer.host}"
                return result
            
            # Uninstall HAProxy
            uninstall_result = await installer.uninstall_haproxy()
            result["uninstall_result"] = uninstall_result
            
            if not uninstall_result["success"]:
                result["message"] = f"HAProxy uninstall failed: {uninstall_result['message']}"
                return result
            
            result["success"] = True
            result["message"] = f"HAProxy uninstalled successfully from {installer.host}"
            
        except Exception as e:
            result["message"] = f"HAProxy uninstall failed on {installer.host}: {str(e)}"
            logger.error(result["message"])
            
        finally:
            installer.close_connection()
            
        return result 