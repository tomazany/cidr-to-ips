import ipaddress
import time
import csv
import psutil
import os
import argparse
from tabulate import tabulate  # For table formatting in benchmark results

# Path to the GeoLite2 ASN CSV file
ASN_CSV_PATH = 'GeoLite2-ASN-Blocks-IPv4.csv'

# Utility function for logging memory usage
def log_memory_usage(message, verbose):
    if verbose:
        process = psutil.Process(os.getpid())
        mem_info = process.memory_info()
        print(f"{message} | Memory usage: {mem_info.rss / (1024 * 1024):.2f} MB")

# Implementation 1: Original version using a set of strings and network.hosts()
def count_unique_ips_set_strings(cidr_list=None, file_path=None, asn_to_cidr=None, verbose=False):
    start_time = time.time()
    if verbose:
        log_memory_usage("Initial memory usage before processing", verbose)

    ip_set = set()
    total_ip_count = 0
    TOTAL_IPV4_ADDRESSES = 2**32

    if cidr_list:
        cidr_ranges = cidr_list.split()
    elif file_path:
        with open(file_path, 'r') as file:
            cidr_ranges = file.read().splitlines()
    else:
        print("No input provided.")
        return

    for entry in cidr_ranges:
        try:
            network_ranges = get_network_ranges(entry, asn_to_cidr)
            for network in network_ranges:
                for ip in network.hosts():
                    ip_set.add(str(ip))
                    total_ip_count += 1
                if verbose:
                    print(f"Processed CIDR: {network} | IP Count: {total_ip_count} | "
                          f"First IP: {network.network_address} | Last IP: {network.broadcast_address}")
                    log_memory_usage(f"After processing {network}", verbose)
        except ValueError as e:
            if verbose:
                print(f"Skipping invalid entry '{entry}': {e}")

    total_unique_ips = len(ip_set)
    unique_ip_percentage = (total_unique_ips / TOTAL_IPV4_ADDRESSES) * 100
    end_time = time.time()
    if verbose:
        log_memory_usage("After processing completed", verbose)
    print("\nSummary:")
    print(f"Total IP addresses (including duplicates): {total_ip_count}")
    print(f"Total unique IP addresses: {total_unique_ips}")
    print(f"Unique IPs as percentage of all possible IPv4 addresses: {unique_ip_percentage:.6f}%")
    print(f"Total time taken: {end_time - start_time:.4f} s")
    return total_ip_count, total_unique_ips, end_time - start_time, psutil.Process(os.getpid()).memory_info().rss / (1024 * 1024)

# Implementation 2: Optimized version using a set of integers and network.hosts()
def count_unique_ips_set_integers(cidr_list=None, file_path=None, asn_to_cidr=None, verbose=False):
    start_time = time.time()
    if verbose:
        log_memory_usage("Initial memory usage before processing", verbose)

    ip_set = set()
    total_ip_count = 0
    TOTAL_IPV4_ADDRESSES = 2**32

    if cidr_list:
        cidr_ranges = cidr_list.split()
    elif file_path:
        with open(file_path, 'r') as file:
            cidr_ranges = file.read().splitlines()
    else:
        print("No input provided.")
        return

    for entry in cidr_ranges:
        try:
            network_ranges = get_network_ranges(entry, asn_to_cidr)
            for network in network_ranges:
                for ip in network.hosts():
                    ip_set.add(int(ip))
                    total_ip_count += 1
                if verbose:
                    print(f"Processed CIDR: {network} | IP Count: {total_ip_count} | "
                          f"First IP: {network.network_address} | Last IP: {network.broadcast_address}")
                    log_memory_usage(f"After processing {network}", verbose)
        except ValueError as e:
            if verbose:
                print(f"Skipping invalid entry '{entry}': {e}")

    total_unique_ips = len(ip_set)
    unique_ip_percentage = (total_unique_ips / TOTAL_IPV4_ADDRESSES) * 100
    end_time = time.time()
    if verbose:
        log_memory_usage("After processing completed", verbose)
    print("\nSummary:")
    print(f"Total IP addresses (including duplicates): {total_ip_count}")
    print(f"Total unique IP addresses: {total_unique_ips}")
    print(f"Unique IPs as percentage of all possible IPv4 addresses: {unique_ip_percentage:.6f}%")
    print(f"Total time taken: {end_time - start_time:.4f} s")
    return total_ip_count, total_unique_ips, end_time - start_time, psutil.Process(os.getpid()).memory_info().rss / (1024 * 1024)

# Implementation 3: Using set of integers with network_address and broadcast_address
def count_unique_ips_network_properties(cidr_list=None, file_path=None, asn_to_cidr=None, verbose=False):
    start_time = time.time()
    if verbose:
        log_memory_usage("Initial memory usage before processing", verbose)

    ip_set = set()
    total_ip_count = 0
    TOTAL_IPV4_ADDRESSES = 2**32

    if cidr_list:
        cidr_ranges = cidr_list.split()
    elif file_path:
        with open(file_path, 'r') as file:
            cidr_ranges = file.read().splitlines()
    else:
        print("No input provided.")
        return

    for entry in cidr_ranges:
        try:
            network_ranges = get_network_ranges(entry, asn_to_cidr)
            for network in network_ranges:
                first_ip = int(network.network_address)
                last_ip = int(network.broadcast_address)
                total_ip_count += (last_ip - first_ip + 1)
                ip_set.update(range(first_ip, last_ip + 1))
                if verbose:
                    print(f"Processed CIDR: {network} | IP Count: {last_ip - first_ip + 1} | "
                          f"First IP: {network.network_address} | Last IP: {network.broadcast_address}")
                    log_memory_usage(f"After processing {network}", verbose)
        except ValueError as e:
            if verbose:
                print(f"Skipping invalid entry '{entry}': {e}")

    total_unique_ips = len(ip_set)
    unique_ip_percentage = (total_unique_ips / TOTAL_IPV4_ADDRESSES) * 100
    end_time = time.time()
    if verbose:
        log_memory_usage("After processing completed", verbose)
    print("\nSummary:")
    print(f"Total IP addresses (including duplicates): {total_ip_count}")
    print(f"Total unique IP addresses: {total_unique_ips}")
    print(f"Unique IPs as percentage of all possible IPv4 addresses: {unique_ip_percentage:.6f}%")
    print(f"Total time taken: {end_time - start_time:.4f} s")
    return total_ip_count, total_unique_ips, end_time - start_time, psutil.Process(os.getpid()).memory_info().rss / (1024 * 1024)

# Implementation 4: Using RangeSet
class RangeSet:
    def __init__(self):
        self.ranges = []

    def add_range(self, start, end):
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

def count_unique_ips_rangeset(cidr_list=None, file_path=None, asn_to_cidr=None, verbose=False):
    start_time = time.time()
    if verbose:
        log_memory_usage("Initial memory usage before processing", verbose)

    range_set = RangeSet()
    total_ip_count = 0
    TOTAL_IPV4_ADDRESSES = 2**32

    if cidr_list:
        cidr_ranges = cidr_list.split()
    elif file_path:
        with open(file_path, 'r') as file:
            cidr_ranges = file.read().splitlines()
    else:
        print("No input provided.")
        return

    for entry in cidr_ranges:
        try:
            network_ranges = get_network_ranges(entry, asn_to_cidr)
            for network in network_ranges:
                first_ip = int(network.network_address)
                last_ip = int(network.broadcast_address)
                total_ip_count += (last_ip - first_ip + 1)
                range_set.add_range(first_ip, last_ip)
                if verbose:
                    print(f"Processed CIDR: {network} | IP Count: {last_ip - first_ip + 1} | "
                          f"First IP: {network.network_address} | Last IP: {network.broadcast_address}")
                    log_memory_usage(f"After processing {network}", verbose)
        except ValueError as e:
            if verbose:
                print(f"Skipping invalid entry '{entry}': {e}")

    total_unique_ips = range_set.total_unique_count()
    unique_ip_percentage = (total_unique_ips / TOTAL_IPV4_ADDRESSES) * 100
    end_time = time.time()
    if verbose:
        log_memory_usage("After processing completed", verbose)
    print("\nSummary:")
    print(f"Total IP addresses (including duplicates): {total_ip_count}")
    print(f"Total unique IP addresses: {total_unique_ips}")
    print(f"Unique IPs as percentage of all possible IPv4 addresses: {unique_ip_percentage:.6f}%")
    print(f"Total time taken: {end_time - start_time:.4f} s")
    return total_ip_count, total_unique_ips, end_time - start_time, psutil.Process(os.getpid()).memory_info().rss / (1024 * 1024)

# Implementation 5: Using RangeSetLazy
class RangeSetLazy:
    def __init__(self):
        self.ranges = []

    def add_range(self, start, end):
        self.ranges.append((start, end))

    def merge_ranges(self):
        if not self.ranges:
            return

        self.ranges.sort()
        merged_ranges = [self.ranges[0]]

        for current in self.ranges[1:]:
            last = merged_ranges[-1]
            if current[0] <= last[1] + 1:
                merged_ranges[-1] = (last[0], max(last[1], current[1]))
            else:
                merged_ranges.append(current)

        self.ranges = merged_ranges

    def total_unique_count(self):
        self.merge_ranges()
        return sum(end - start + 1 for start, end in self.ranges)

def count_unique_ips_lazy(cidr_list=None, file_path=None, asn_to_cidr=None, verbose=False):
    start_time = time.time()
    if verbose:
        log_memory_usage("Initial memory usage before processing", verbose)

    range_set = RangeSetLazy()
    total_ip_count = 0
    TOTAL_IPV4_ADDRESSES = 2**32

    if cidr_list:
        cidr_ranges = cidr_list.split()
    elif file_path:
        with open(file_path, 'r') as file:
            cidr_ranges = file.read().splitlines()
    else:
        print("No input provided.")
        return

    for entry in cidr_ranges:
        try:
            network_ranges = get_network_ranges(entry, asn_to_cidr)
            for network in network_ranges:
                first_ip = int(network.network_address)
                last_ip = int(network.broadcast_address)
                total_ip_count += (last_ip - first_ip + 1)
                range_set.add_range(first_ip, last_ip)
                if verbose:
                    print(f"Processed CIDR: {network} | IP Count: {last_ip - first_ip + 1} | "
                          f"First IP: {network.network_address} | Last IP: {network.broadcast_address}")
                    log_memory_usage(f"After processing {network}", verbose)
        except ValueError as e:
            if verbose:
                print(f"Skipping invalid entry '{entry}': {e}")

    total_unique_ips = range_set.total_unique_count()
    unique_ip_percentage = (total_unique_ips / TOTAL_IPV4_ADDRESSES) * 100
    end_time = time.time()
    if verbose:
        log_memory_usage("After processing completed", verbose)
    print("\nSummary:")
    print(f"Total IP addresses (including duplicates): {total_ip_count}")
    print(f"Total unique IP addresses: {total_unique_ips}")
    print(f"Unique IPs as percentage of all possible IPv4 addresses: {unique_ip_percentage:.6f}%")
    print(f"Total time taken: {end_time - start_time:.4f} s")
    return total_ip_count, total_unique_ips, end_time - start_time, psutil.Process(os.getpid()).memory_info().rss / (1024 * 1024)

# Helper functions
def get_network_ranges(entry, asn_to_cidr):
    if entry.startswith("AS"):
        asn = int(entry[2:])
        if asn in asn_to_cidr:
            return asn_to_cidr[asn]
        else:
            raise ValueError(f"ASN '{entry}' not found in database.")
    else:
        return [ipaddress.ip_network(entry, strict=False)]

# Load ASN to CIDR mapping
def load_asn_to_cidr_mapping(asn_csv_path, verbose):
    if verbose:
        print("Loading ASN-to-CIDR mappings...")
    start_time = time.time()
    if verbose:
        log_memory_usage("Before loading ASN-to-CIDR mappings", verbose)
    
    asn_to_cidr = {}
    with open(asn_csv_path, newline='') as csvfile:
        reader = csv.reader(csvfile)
        next(reader)
        for row in reader:
            network, asn = row[0], row[1]
            asn = int(asn[2:]) if asn.startswith("AS") else int(asn)
            if asn not in asn_to_cidr:
                asn_to_cidr[asn] = []
            asn_to_cidr[asn].append(ipaddress.ip_network(network))
    
    if verbose:
        log_memory_usage("After loading ASN-to-CIDR mappings", verbose)
        print(f"ASN-to-CIDR mappings loaded in {time.time() - start_time:.4f} s.")
    return asn_to_cidr

# Benchmarking function
def benchmark_implementations(cidr_list, file_path, asn_to_cidr, verbose=False):
    implementations = {
        1: (count_unique_ips_set_strings, "Original version using set of strings with network.hosts()"),
        2: (count_unique_ips_set_integers, "Optimized version using set of integers with network.hosts()"),
        3: (count_unique_ips_network_properties, "Optimized version using network_address and broadcast_address"),
        4: (count_unique_ips_rangeset, "Further optimized using RangeSet"),
        5: (count_unique_ips_lazy, "Final optimized using RangeSetLazy"),
    }

    results = []
    print("\nStarting benchmark...")
    for i, (func, description) in implementations.items():
        print(f"Evaluating implementation {i} of {len(implementations)}...")
        _, _, time_taken, memory_used = func(cidr_list=cidr_list, file_path=file_path, asn_to_cidr=asn_to_cidr, verbose=False)
        results.append((f"Implementation {i}", f"{time_taken:.4f} s", f"{memory_used:.2f} MB", description))

    print("\nBenchmark Results:")
    print(tabulate(results, headers=["Implementation", "Time Taken", "Memory Used", "Details"], numalign="right"))

# Main function
def main():
    parser = argparse.ArgumentParser(
        description="Benchmark different implementations of IP range processing.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        '-f', '--file', type=str,
        help="Path to a file containing CIDR ranges or ASN numbers (one per line)."
    )
    parser.add_argument(
        '-l', '--list', type=str,
        help="Directly provide a space-separated list of CIDR ranges or ASN numbers."
    )
    parser.add_argument(
        '-i', '--implementation', type=int, choices=[1, 2, 3, 4, 5],
        help="Select a specific implementation to run (1-5)."
    )
    parser.add_argument(
        '-b', '--benchmark', action='store_true',
        help="Run all implementations in benchmarking mode."
    )
    parser.add_argument(
        '-v', '--verbose', action='store_true',
        help="Enable verbose mode to log memory usage information."
    )

    args = parser.parse_args()

    if not args.file and not args.list:
        print("No input provided. Use '-h' or '--help' for usage information.")
        return

    asn_to_cidr = load_asn_to_cidr_mapping(ASN_CSV_PATH, args.verbose)

    if args.benchmark:
        benchmark_implementations(cidr_list=args.list, file_path=args.file, asn_to_cidr=asn_to_cidr, verbose=args.verbose)
    elif args.implementation:
        implementations = {
            1: count_unique_ips_set_strings,
            2: count_unique_ips_set_integers,
            3: count_unique_ips_network_properties,
            4: count_unique_ips_rangeset,
            5: count_unique_ips_lazy,
        }
        func = implementations.get(args.implementation, count_unique_ips_lazy)
        func(cidr_list=args.list, file_path=args.file, asn_to_cidr=asn_to_cidr, verbose=args.verbose)
    else:
        count_unique_ips_lazy(cidr_list=args.list, file_path=args.file, asn_to_cidr=asn_to_cidr, verbose=args.verbose)

if __name__ == "__main__":
    main()
