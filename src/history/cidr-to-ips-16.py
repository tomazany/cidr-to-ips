import ipaddress
import time
import csv
import psutil
import os
import argparse

# Path to the GeoLite2 ASN CSV file
ASN_CSV_PATH = 'GeoLite2-ASN-Blocks-IPv4.csv'

class RangeSetLazy:
    def __init__(self):
        self.ranges = []

    def add_range(self, start, end):
        """Adds a range [start, end] without immediate merging."""
        self.ranges.append((start, end))

    def merge_ranges(self):
        """Merges overlapping or contiguous ranges."""
        if not self.ranges:
            return

        self.ranges.sort()
        merged_ranges = [self.ranges[0]]

        for current in self.ranges[1:]:
            last = merged_ranges[-1]
            if current[0] <= last[1] + 1:  # Overlapping or contiguous
                merged_ranges[-1] = (last[0], max(last[1], current[1]))
            else:
                merged_ranges.append(current)

        self.ranges = merged_ranges

    def total_unique_count(self):
        """Calculates the total number of unique integers covered by the ranges."""
        self.merge_ranges()  # Ensure ranges are merged before counting
        return sum(end - start + 1 for start, end in self.ranges)

    def __repr__(self):
        return f"RangeSetLazy({self.ranges})"

def log_memory_usage(message, verbose):
    """Logs the current memory usage of the process if verbose mode is enabled."""
    if verbose:
        process = psutil.Process(os.getpid())
        mem_info = process.memory_info()
        print(f"{message} | Memory usage: {mem_info.rss / (1024 * 1024):.2f} MB")

def load_asn_to_cidr_mapping(asn_csv_path, verbose):
    print("Loading ASN-to-CIDR mappings...")
    load_start_time = time.time()
    log_memory_usage("Before loading ASN-to-CIDR mappings", verbose)
    
    asn_to_cidr = {}
    with open(asn_csv_path, newline='') as csvfile:
        reader = csv.reader(csvfile)
        next(reader)  # Skip header row
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
    log_memory_usage("After loading ASN-to-CIDR mappings", verbose)
    print(f"ASN-to-CIDR mappings loaded. Time taken: {load_end_time - load_start_time:.4f} seconds.")
    return asn_to_cidr

def count_unique_ips_lazy(cidr_list=None, file_path=None, verbose=False):
    start_time = time.time()
    log_memory_usage("Initial memory usage before processing", verbose)

    range_set = RangeSetLazy()
    total_ip_count = 0  # Counter for all IP addresses, including duplicates
    TOTAL_IPV4_ADDRESSES = 2**32

    # Load ASN-to-CIDR mappings from CSV
    asn_to_cidr = load_asn_to_cidr_mapping(ASN_CSV_PATH, verbose)

    # Check if input is a list of CIDR ranges or ASNs
    if cidr_list:
        cidr_ranges = cidr_list.split()
    elif file_path:
        with open(file_path, 'r') as file:
            cidr_ranges = file.read().splitlines()
    else:
        print("No input provided. Use '-h' or '--help' for usage information.")
        return

    print("\nProcessing CIDR and ASN entries...")
    
    for entry in cidr_ranges:
        try:
            # Determine if the entry is an ASN or CIDR range
            if entry.startswith("AS"):  # ASN format, e.g., "AS12345"
                asn = int(entry[2:])  # Strip 'AS' prefix and parse as integer
                if asn in asn_to_cidr:
                    network_ranges = asn_to_cidr[asn]
                else:
                    print(f"ASN '{entry}' not found in database.")
                    continue
            else:
                # Assume entry is a CIDR range
                network_ranges = [ipaddress.ip_network(entry, strict=False)]

            # Process each network range associated with this entry
            for network in network_ranges:
                first_ip = int(network.network_address)
                last_ip = int(network.broadcast_address)
                ip_count = last_ip - first_ip + 1

                # Increment total IP count (including duplicates)
                total_ip_count += ip_count

                # Add the range to the RangeSetLazy without merging immediately
                range_set.add_range(first_ip, last_ip)

                # Output information for the current CIDR range
                print(f"Processed CIDR: {network} | IP Count: {ip_count} | "
                      f"First IP: {ipaddress.ip_address(first_ip)} | Last IP: {ipaddress.ip_address(last_ip)}")

                # Log memory usage after processing each CIDR range
                log_memory_usage(f"After processing {network}", verbose)

        except ValueError as e:
            print(f"Skipping invalid entry '{entry}': {e}")

    # Total unique IPs and percentage calculation
    total_unique_ips = range_set.total_unique_count()
    unique_ip_percentage = (total_unique_ips / TOTAL_IPV4_ADDRESSES) * 100

    # Log memory usage before final summary
    log_memory_usage("Before final summary", verbose)

    # Display the total count of unique IPs and percentage
    print("\nSummary:")
    print("Total IP addresses (including duplicates):", total_ip_count)
    print("Total unique IP addresses:", total_unique_ips)
    print(f"Unique IPs as percentage of all possible IPv4 addresses: {unique_ip_percentage:.6f}%")

    # Display the time taken
    end_time = time.time()
    print(f"Total time taken: {end_time - start_time:.4f} seconds")
    log_memory_usage("After processing completed", verbose)

def main():
    parser = argparse.ArgumentParser(
        description="Process IP ranges and ASNs to calculate unique IP counts and ranges.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        '-f', '--file', type=str,
        help="Path to a file containing CIDR ranges or ASN numbers (one per line)."
    )
    parser.add_argument(
        '-l', '--list', type=str,
        help="Directly provide a space-separated list of CIDR ranges or ASN numbers (e.g., 'AS12345 192.168.1.0/24')."
    )
    parser.add_argument(
        '-v', '--verbose', action='store_true',
        help="Enable verbose mode to log memory usage information."
    )

    args = parser.parse_args()

    if not args.file and not args.list:
        print("No input provided. Use '-h' or '--help' for usage information.")
        return

    count_unique_ips_lazy(cidr_list=args.list, file_path=args.file, verbose=args.verbose)

if __name__ == "__main__":
    main()
