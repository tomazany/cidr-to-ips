import ipaddress

def count_unique_ips_and_display_ranges_optimized(cidr_list=None, file_path=None):
    ip_set = set()
    cidr_info = []

    # Check if input is a list of CIDR ranges
    if cidr_list:
        cidr_ranges = cidr_list.split()
    elif file_path:
        with open(file_path, 'r') as file:
            cidr_ranges = file.read().splitlines()
    else:
        raise ValueError("Please provide either a list of CIDR ranges or a file path.")

    for cidr in cidr_ranges:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            hosts = list(network.hosts())
            if hosts:
                first_ip = int(hosts[0])
                last_ip = int(hosts[-1])
                ip_count = len(hosts)
            else:
                first_ip = last_ip = int(network.network_address)
                ip_count = 1  # Single IP case for /32 mask

            # Store the information for each CIDR range
            cidr_info.append({
                "cidr": cidr,
                "count": ip_count,
                "first_ip": ipaddress.ip_address(first_ip),
                "last_ip": ipaddress.ip_address(last_ip)
            })

            # Update the unique IP set with integers instead of strings
            ip_set.update(range(first_ip, last_ip + 1))
        except ValueError as e:
            print(f"Skipping invalid CIDR range '{cidr}': {e}")

    # Display information for each CIDR range
    print("CIDR Range Information:")
    for info in cidr_info:
        print(f"CIDR: {info['cidr']} | IP Count: {info['count']} | "
              f"First IP: {info['first_ip']} | Last IP: {info['last_ip']}")

    # Display the total count of unique IPs
    print("\nTotal unique IP addresses:", len(ip_set))

# Example usage
cidr_input = "192.168.1.0/24 10.0.0.0/8"
file_path = "cidr_ranges.txt"  # Use this if you have a file input

# Count unique IPs for a list input
# print("Unique IPs (list input):")
# count_unique_ips_and_display_ranges_optimized(cidr_list=cidr_input)

# Count unique IPs for a file input
print("Unique IPs (file input):")
count_unique_ips_and_display_ranges_optimized(file_path=file_path)
