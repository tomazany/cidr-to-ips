import ipaddress
import time
import csv
import tracemalloc

# Path to the GeoLite2 ASN CSV file
ASN_CSV_PATH = 'GeoLite2-ASN-Blocks-IPv4.csv'

def load_asn_to_cidr_mapping(asn_csv_path):
    print("Loading ASN-to-CIDR mappings...")
    load_start_time = time.time()  # Start timing the CSV load
    
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
    print(f"ASN-to-CIDR mappings loaded. Time taken: {load_end_time - load_start_time:.4f} seconds.")
    return asn_to_cidr

def count_unique_ips_and_display_ranges_optimized(cidr_list=None, file_path=None):
    start_time = time.time()  # Start time for benchmarking
    tracemalloc.start()  # Start memory tracking

    ip_set = set()
    total_ip_count = 0  # Counter for all IP addresses, including duplicates
    TOTAL_IPV4_ADDRESSES = 2**32

    # Load ASN-to-CIDR mappings from CSV
    asn_to_cidr = load_asn_to_cidr_mapping(ASN_CSV_PATH)

    # Check if input is a list of CIDR ranges or ASNs
    if cidr_list:
        cidr_ranges = cidr_list.split()
    elif file_path:
        with open(file_path, 'r') as file:
            cidr_ranges = file.read().splitlines()
    else:
        raise ValueError("Please provide either a list of CIDR ranges/ASNs or a file path.")

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

                # Update the unique IP set with range directly
                ip_set.update(range(first_ip, last_ip + 1))

                # Output information for the current CIDR range
                print(f"Processed CIDR: {network} | IP Count: {ip_count} | "
                      f"First IP: {ipaddress.ip_address(first_ip)} | Last IP: {ipaddress.ip_address(last_ip)}")

        except ValueError as e:
            print(f"Skipping invalid entry '{entry}': {e}")

    # Total unique IPs and percentage calculation
    total_unique_ips = len(ip_set)
    unique_ip_percentage = (total_unique_ips / TOTAL_IPV4_ADDRESSES) * 100

    # Display the total count of unique IPs and percentage
    print("\nSummary:")
    print("Total IP addresses (including duplicates):", total_ip_count)
    print("Total unique IP addresses:", total_unique_ips)
    print(f"Unique IPs as percentage of all possible IPv4 addresses: {unique_ip_percentage:.6f}%")

    # Display the time taken
    end_time = time.time()
    print(f"Total time taken: {end_time - start_time:.4f} seconds")

    # Stop memory tracking and display peak memory usage
    current, peak = tracemalloc.get_traced_memory()
    print(f"Peak memory usage: {peak / (1024 * 1024):.2f} MB")
    tracemalloc.stop()

# Example usage
cidr_input = "192.168.1.0/24 AS15169"
file_path = "cidr_asn_input.txt"  # Use this if you have a file input

# Count unique IPs for a list input
# print("Unique IPs (list input):")
# count_unique_ips_and_display_ranges_optimized(cidr_list=cidr_input)

# Count unique IPs for a file input
print("Unique IPs (file input):")
count_unique_ips_and_display_ranges_optimized(file_path=file_path)