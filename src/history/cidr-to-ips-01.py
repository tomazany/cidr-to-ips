import ipaddress

def count_unique_ips(cidr_list=None, file_path=None):
    ip_set = set()

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
            # Convert each CIDR range to an IP network and add each IP to the set
            network = ipaddress.ip_network(cidr, strict=False)
            ip_set.update(network.hosts())
        except ValueError as e:
            print(f"Skipping invalid CIDR range '{cidr}': {e}")

    return len(ip_set)

# Example usage
cidr_input = "192.168.1.0/24 10.0.0.0/8"
file_path = "cidr_ranges.txt"  # Use this if you have a file input

# Count unique IPs for a list input
# print("Unique IPs (list input):", count_unique_ips(cidr_list=cidr_input))

# Count unique IPs for a file input
print("Unique IPs (file input):", count_unique_ips(file_path=file_path))