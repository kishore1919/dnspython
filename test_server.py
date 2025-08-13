#!/usr/bin/env python3

import subprocess
import time

def test_dns_time_server():
    """Test the DNS time server functionality"""
    print("Testing DNS Time Server")
    print("=" * 30)
    
    # Start the server in the background
    print("Starting DNS time server...")
    server_process = subprocess.Popen(["python3", "main.py"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    # Give the server time to start
    time.sleep(3)
    
    try:
        # Test TXT query
        print("\n1. Testing TXT record query:")
        result = subprocess.run(["dig", "@localhost", "-p", "5353", "time.local", "TXT"], 
                              capture_output=True, text=True)
        print(result.stdout)
        
        # Test A record query
        print("\n2. Testing A record query:")
        result = subprocess.run(["dig", "@localhost", "-p", "5353", "time.local", "A"], 
                              capture_output=True, text=True)
        print(result.stdout)
        
    finally:
        # Stop the server
        print("Stopping DNS time server...")
        server_process.terminate()
        server_process.wait()
        print("Server stopped.")

if __name__ == "__main__":
    test_dns_time_server()