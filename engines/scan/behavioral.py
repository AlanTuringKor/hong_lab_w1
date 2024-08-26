import requests
import subprocess
import psutil
from scapy.all import sniff

# Function to submit a file to Cuckoo Sandbox
def submit_to_cuckoo(file_path):
    url = "http://localhost:8090/tasks/create/file"
    with open(file_path, 'rb') as f:
        files = {'file': (file_path, f)}
        response = requests.post(url, files=files)
        return response.json()

# Function to get the report from Cuckoo Sandbox
def get_report(task_id):
    url = f"http://localhost:8090/tasks/report/{task_id}"
    response = requests.get(url)
    return response.json()

# Function to monitor system calls using Sysdig
def monitor_system_calls(pid):
    cmd = f"sysdig proc.pid={pid}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout

# Function to monitor a process using psutil
def monitor_process(pid):
    process = psutil.Process(pid)
    info = {
        "pid": process.pid,
        "name": process.name(),
        "exe": process.exe(),
        "cmdline": process.cmdline(),
        "status": process.status(),
        "create_time": process.create_time(),
        "cpu_times": process.cpu_times(),
        "memory_info": process.memory_info(),
        "open_files": process.open_files(),
        "connections": process.connections()
    }
    return info

# Function to monitor network traffic using Scapy
def packet_callback(packet):
    print(packet.summary())

def monitor_network(interface):
    sniff(iface=interface, prn=packet_callback, store=0)

# Main function to perform behavioral analysis
def perform_behavioral_analysis(file_path, pid, interface):
    # Step 1: Sandboxing with Cuckoo Sandbox
    print("Submitting file to Cuckoo Sandbox...")
    task = submit_to_cuckoo(file_path)
    task_id = task['task_id']
    report = get_report(task_id)
    print("Cuckoo Sandbox Report:")
    print(report)

    # Step 2: System Call Monitoring with Sysdig
    print("Monitoring system calls with Sysdig...")
    sysdig_output = monitor_system_calls(pid)
    print("Sysdig Output:")
    print(sysdig_output)

    # Step 3: Process Monitoring with psutil
    print("Monitoring process with psutil...")
    process_info = monitor_process(pid)
    print("Process Info:")
    print(process_info)

    # Step 4: Network Traffic Analysis with Scapy
    print("Monitoring network traffic with Scapy...")
    monitor_network(interface)

# Example usage
file_path = "/path/to/file"
pid = 1234  # Replace with the actual process ID
interface = "eth0"  # Replace with the actual network interface
perform_behavioral_analysis(file_path, pid, interface)