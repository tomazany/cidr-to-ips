# Version 27

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

# Helper function for processing input CIDR or ASN
def process_input(cidr_list, file_path, asn_to_cidr, verbose):
    if cidr_list:
        return cidr_list.split()
    elif file_path:
        with open(file_path, 'r') as file:
            return file.read().splitlines()
    else:
        print("No input provided. Use '-h' or '--help' for usage information.")
        return None

# Base class for different implementations
class Implementation:
    def __init__(self):
        self.ip_set = None

    def set_up(self):
        """Sets up the data structure for storing IPs."""
        self.ip_set = set()

    def process_network(self, network):
        """Processes a network and adds its IPs to the data structure."""
        raise NotImplementedError("Must be implemented in subclasses.")

    def total_unique_count(self):
        """Calculates and returns the total count of unique IPs."""
        return len(self.ip_set)

# Implementation 1: Using a set of IPv4Address objects
class ImplementationIPv4Objects(Implementation):
    def process_network(self, network):
        for ip in network:
            self.ip_set.add(ip)

# Implementation 2: Using a set of integers
class ImplementationIntegers(Implementation):
    def process_network(self, network):
        for ip in network:
            self.ip_set.add(int(ip))

# Implementation 3: Using network properties with integers
class ImplementationNetworkProperties(Implementation):
    def process_network(self, network):
        first_ip = int(network.network_address)
        last_ip = int(network.broadcast_address)
        self.ip_set.update(range(first_ip, last_ip + 1))

# Data structure for Implementation 4: RangeSet
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

# Implementation 4: Using RangeSet
class ImplementationRangeSet(Implementation):
    def set_up(self):
        self.ip_set = RangeSet()

    def process_network(self, network):
        first_ip = int(network.network_address)
        last_ip = int(network.broadcast_address)
        self.ip_set.add_range(first_ip, last_ip)

    def total_unique_count(self):
        return self.ip_set.total_unique_count()

# Data structure for Implementation 5: RangeSetLazy
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

# Implementation 5: Using RangeSetLazy
class ImplementationRangeSetLazy(Implementation):
    def set_up(self):
        self.ip_set = RangeSetLazy()

    def process_network(self, network):
        first_ip = int(network.network_address)
        last_ip = int(network.broadcast_address)
        self.ip_set.add_range(first_ip, last_ip)

    def total_unique_count(self):
        return self.ip_set.total_unique_count()

# Helper function to get network ranges
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

# Common function for running implementations
def run_implementation(implementation_class, cidr_ranges, asn_to_cidr, verbose=False, quiet=False):
    start_time = time.time()
    if verbose:
        log_memory_usage("Initial memory usage before processing", verbose)

    implementation = implementation_class()
    implementation.set_up()
    total_ip_count = 0

    for entry in cidr_ranges:
        try:
            network_ranges = get_network_ranges(entry, asn_to_cidr)
            for network in network_ranges:
                total_ip_count += network.num_addresses
                implementation.process_network(network)

                if not quiet and not verbose:
                    print(f"Processed CIDR: {network} | IP Count: {network.num_addresses} | "
                          f"First IP: {network.network_address} | Last IP: {network.broadcast_address}")
        except ValueError as e:
            if verbose:
                print(f"Skipping invalid entry '{entry}': {e}")

    total_unique_ips = implementation.total_unique_count()
    TOTAL_IPV4_ADDRESSES = 2**32
    unique_ip_percentage = (total_unique_ips / TOTAL_IPV4_ADDRESSES) * 100
    end_time = time.time()

    if verbose:
        log_memory_usage("After processing completed", verbose)

    if not quiet or verbose:
        print("\nSummary:")
        print(f"Total IP addresses (including duplicates): {total_ip_count}")
        print(f"Total unique IP addresses: {total_unique_ips}")
        print(f"Unique IPs as percentage of all possible IPv4 addresses: {unique_ip_percentage:.6f}%")
        print(f"Total time taken: {end_time - start_time:.4f} s")

    return total_ip_count, total_unique_ips, end_time - start_time, psutil.Process(os.getpid()).memory_info().rss / (1024 * 1024)

# Benchmarking function
def benchmark_implementations(cidr_ranges, asn_to_cidr, verbose=False, quiet=False):
    implementations = {
        1: (ImplementationIPv4Objects, "Using a set of IPv4Address objects"),
        2: (ImplementationIntegers, "Using a set of integers"),
        3: (ImplementationNetworkProperties, "Using network properties with a set of integers"),
        4: (ImplementationRangeSet, "Using a RangeSet"),
        5: (ImplementationRangeSetLazy, "Using a RangeSetLazy"),
    }

    results = []
    print("\nStarting benchmark...")

    for i, (implementation_class, description) in implementations.items():
        if not quiet:
            print(f"Evaluating implementation {i} of {len(implementations)}...")

        _, total_unique_ips, time_taken, memory_used = run_implementation(
            implementation_class, cidr_ranges, asn_to_cidr, verbose=verbose, quiet=quiet
        )

        results.append((f"{i}", f"{time_taken:.4f} s", f"{total_unique_ips:,}", f"{memory_used:.2f} MB", description))

    print("\nBenchmark Results:")
    print(tabulate(results, headers=["#", "Time Taken", "Unique IPs", "Memory Used", "Details"], numalign="right"))

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
    parser.add_argument(
        '-q', '--quiet', action='store_true',
        help="Run in quiet mode to suppress detailed output."
    )

    args = parser.parse_args()

    asn_to_cidr = load_asn_to_cidr_mapping(ASN_CSV_PATH, args.verbose)
    cidr_ranges = process_input(args.list, args.file, asn_to_cidr, args.verbose)

    if not cidr_ranges:
        return

    if args.benchmark:
        benchmark_implementations(cidr_ranges, asn_to_cidr, verbose=args.verbose, quiet=args.quiet)
    elif args.implementation:
        implementations = {
            1: ImplementationIPv4Objects,
            2: ImplementationIntegers,
            3: ImplementationNetworkProperties,
            4: ImplementationRangeSet,
            5: ImplementationRangeSetLazy,
        }
        implementation_class = implementations.get(args.implementation, ImplementationIPv4Objects)
        run_implementation(implementation_class, cidr_ranges, asn_to_cidr, verbose=args.verbose, quiet=args.quiet)
    else:
        run_implementation(ImplementationIPv4Objects, cidr_ranges, asn_to_cidr, verbose=args.verbose, quiet=args.quiet)

if __name__ == "__main__":
    main()
