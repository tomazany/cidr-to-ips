import ipaddress
import time
import csv
import psutil
import os
from concurrent.futures import ThreadPoolExecutor

# Path to the GeoLite2 ASN CSV file
ASN_CSV_PATH = 'GeoLite2-ASN-Blocks-IPv4.csv'

class RangeSet:
    def __init__(self):
        self.ranges = []

    def add_range(self, start, end):
        """Adds a range [start, end] and merges overlapping or contiguous ranges."""
        new_range = (start, end)
        updated_ranges = []

        for current_range in self.ranges:
            if new_range[1] < current_range[0] - 1:
                updated_ranges.append(current_range)
            elif new_range[0] > current_range[1] + 1:
                updated_ranges.append(current_range)
            else:
                new_range = (min(new_range[0], current_range[0]), max(new_range[1], current_range[1]))

        updated_ranges.append(new_range)
        updated_ranges.sort()
        self.ranges = updated_ranges

    def total_unique_count(self):
        return sum(end - start + 1 for start, end in self.ranges)

    def __repr__(self):
        return f"RangeSet({self.ranges})"

def log_memory_usage(message):
    process = psutil.Process(os.getpid())
    mem_info = process.memory_info()
    print(f"{message} | Memory usage: {mem_info.rss / (1024 * 1024):.2f} MB")

def load_asn_to_cidr_mapping(asn_csv_path):
    print("Loading ASN-to-CIDR mappings...")
    load_start_time = time.time()
    log_memory_usage("Before loading ASN-to-CIDR mappings")
    
    asn_to_cidr = {}
    with open(asn_csv_path, newline='') as csvfile:
        reader = csv.reader(csvfile)
        next(reader)
        for row in reader:
            network, asn = row[0], row[1]
            if asn.startswith("AS"):
                asn = int(asn[2:])
            else:
                asn = int(asn)
            if asn not in asn_to_cidr:
                asn_to_cidr[asn] = []
            asn_to_cidr[asn].append(ipaddress.ip_network(network))
    
    load_end_time = time.time()
    log_memory_usage("After loading ASN-to-CIDR mappings")
    print(f"ASN-to-CIDR mappings loaded. Time taken: {load_end_time - load_start_time:.4f} seconds.")
    return asn_to_cidr

def process_entry(entry, asn_to_cidr, range_set):
    try:
        if entry.startswith("AS"):
            asn = int(entry[2:])
            if asn in asn_to_cidr:
                network_ranges = asn_to_cidr[asn]
            else:
                print(f"ASN '{entry}' not found in database.")
                return
        else:
            network_ranges = [ipaddress.ip_network(entry, strict=False)]

        for network in network_ranges:
            first_ip = int(network.network_address)
            last_ip = int(network.broadcast_address)
            range_set.add_range(first_ip, last_ip)

            print(f"Processed CIDR: {network} | IP Count: {last_ip - first_ip + 1} | "
                  f"First IP: {ipaddress.ip_address(first_ip)} | Last IP: {ipaddress.ip_address(last_ip)}")

    except ValueError as e:
        print(f"Skipping invalid entry '{entry}': {e}")

def count_unique_ips_parallel(cidr_list=None, file_path=None):
    start_time = time.time()
    log_memory_usage("Initial memory usage before processing")

    range_set = RangeSet()
    TOTAL_IPV4_ADDRESSES = 2**32

    asn_to_cidr = load_asn_to_cidr_mapping(ASN_CSV_PATH)

    if cidr_list:
        cidr_ranges = cidr_list.split()
    elif file_path:
        with open(file_path, 'r') as file:
            cidr_ranges = file.read().splitlines()
    else:
        raise ValueError("Please provide either a list of CIDR ranges/ASNs or a file path.")

    print("\nProcessing CIDR and ASN entries in parallel...")

    with ThreadPoolExecutor() as executor:
        futures = [executor.submit(process_entry, entry, asn_to_cidr, range_set) for entry in cidr_ranges]
        for future in futures:
            future.result()  # Ensure each task completes

    total_unique_ips = range_set.total_unique_count()
    unique_ip_percentage = (total_unique_ips / TOTAL_IPV4_ADDRESSES) * 100

    log_memory_usage("Before final summary")

    print("\nSummary:")
    print("Total unique IP addresses:", total_unique_ips)
    print(f"Unique IPs as percentage of all possible IPv4 addresses: {unique_ip_percentage:.6f}%")

    end_time = time.time()
    print(f"Total time taken: {end_time - start_time:.4f} seconds")
    log_memory_usage("After processing completed")

# Example usage
cidr_input = "192.168.1.0/24 AS15169"
file_path = "cidr_asn_input.txt"

print("Unique IPs (list input with parallel processing):")
count_unique_ips_parallel(file_path=file_path)