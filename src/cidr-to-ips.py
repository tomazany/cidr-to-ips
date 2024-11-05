# Version 28
#   - first version manually modified


import ipaddress
import time
import csv
import psutil
import os
import sys
import gc
import argparse
import concurrent.futures
import inspect
import textwrap
from tabulate import tabulate
from collections import namedtuple


# ============================ CONSTANTS ===============================

# path to the GeoLite2 ASN CSV file
ASN_CSV_PATH = 'GeoLite2-ASN-Blocks-IPv4.csv'

# number of all IPv4 addresses and public (not reserved) addresses
TOTAL_IPV4_ADDRESSES = 2**32
TOTAL_PUBLIC_IPV4_ADDRESSES = TOTAL_IPV4_ADDRESSES - 571605992
TOTAL_PUBLIC_IPV4_ADDRESSES_MIN = TOTAL_IPV4_ADDRESSES - 592709864

# Unicode zero-width space
U_X200B = '​'


# ========================= HELPER FUNCTIONS ===========================

# format IP stats
def fip(i, a=TOTAL_PUBLIC_IPV4_ADDRESSES_MIN):
    percentage = (i / a) * 100
    return str(f"{percentage:.6f}%")

# format memory stats in MB
def fmem(i):
    return str(f"{i / (1024 * 1024):.2f} MB")

# format time stats in s
def ftime(i):
    return str(f"{i:.4f} s")

# get current timestamp
def gtime():
    return time.time()

# get current memory stats
def gmem():
    return psutil.Process(os.getpid()).memory_info().rss

# return carriage and clear line (for progress messages)
def clear_line():
    print("\r\u001b[0K", end="", flush=True)

# Terminal ANSI Escape sequences
class ts:
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    DARKCYAN = '\033[36m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    B = BOLD = '\033[1m'
    D = DIM = '\033[2m'
    N = NORMAL = '\033[22m'
    U = UNDERLINE = '\033[4m'
    BLINK = '\033[5m'
    R = REVERSE = '\033[7m'
    C = CONCEALED = '\033[7m'
    E = END = '\033[0m'

    def safe(s, d=None):
        if d is None:
            if sys.stdout.isatty():
                return s
            else:
                return ""
        else:
            if sys.stdout.isatty():
                return d + s + ts.E
            else:
                return s
    def b(s):
        return ts.safe(s, ts.B)
    def d(s):
        return ts.safe(s, ts.D)
    def u(s):
        return ts.safe(s, ts.U)


# ========================= DATA STRUCTURES ============================

# data structure for RangeSet implementation
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

# data structure for RangeSetLazy implementation
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

# base class for different implementations
class Implementation:
    def __init__(self):
        self.ip_set = None

    def set_up(self):
        """Sets up the data structure for storing IPs."""
        self.ip_set = set()

    def dont_bench():
        """Exclude this implementation from benchmark."""
        return False

    def process_network(self, network):
        """Processes a network and adds its IPs to the data structure."""
        raise NotImplementedError("Must be implemented in subclasses.")

    def total_unique_count(self):
        """Calculates and returns the total count of unique IPs."""
        return len(self.ip_set)


# ========================= IMPLEMENTATIONS ============================

# Implementation 1: Using a set of IPv4Address objects with an iterator
class ImplementationObjectsIterator(Implementation):
    """Objects Iterator - IPv4Address, for, add"""
    def process_network(self, network):
        for ip in network:
            self.ip_set.add(ip)

# Implementation 2: Using a set of IPv4Address objects with a list
class ImplementationObjectsList(Implementation):
    """Objects List - IPv4Address, list, update"""
    def process_network(self, network):
        ips = list(network)
        self.ip_set.update(ips)

# Implementation 3: Using a set of integers with an iterator
class ImplementationIntegersIterator(Implementation):
    """Integers Iterator - int, for, add"""
    def process_network(self, network):
        for ip in network:
            self.ip_set.add(int(ip))

# Implementation 4: Using a set of integers with a list (1)
class ImplementationIntegersList1(Implementation):
    """Integers List (1) - int, list, update"""
    def process_network(self, network):
        ips = list(network)
        self.ip_set.update(int(ip) for ip in ips)

# Implementation 5: Using a set of integers with a list (2)
class ImplementationIntegersList2(Implementation):
    """Integers List (2) - int, network, update"""
    def process_network(self, network):
        self.ip_set.update(int(ip) for ip in network)

# Implementation 6: Using a set of integers with a list and a range
class ImplementationIntegersListRange(Implementation):
    """Integers List Range - int, list, update, range"""
    def process_network(self, network):
        ips = list(network)
        first_ip = int(ips[0])
        last_ip = int(ips[-1])
        self.ip_set.update(range(first_ip, last_ip + 1))

# Implementation 7: Using a set of integers with network elements
class ImplementationNetworkElements(Implementation):
    """Network Elements - int, network, update, range"""
    def process_network(self, network):
        first_ip = int(network[0])
        last_ip = int(network[-1])
        self.ip_set.update(range(first_ip, last_ip + 1))

# Implementation 8: Using a set of integers with network properties
class ImplementationNetworkProperties(Implementation):
    """Network Properties - int, network properties, update, range"""
    def process_network(self, network):
        first_ip = int(network.network_address)
        last_ip = int(network.broadcast_address)
        self.ip_set.update(range(first_ip, last_ip + 1))

# Implementation 9: Using RangeSet
class ImplementationRangeSet(Implementation):
    """RangeSet - int, add_range"""
    def set_up(self):
        self.ip_set = RangeSet()

    def process_network(self, network):
        first_ip = int(network.network_address)
        last_ip = int(network.broadcast_address)
        self.ip_set.add_range(first_ip, last_ip)

    def total_unique_count(self):
        return self.ip_set.total_unique_count()

# Implementation 10: Using RangeSetLazy
class ImplementationRangeSetLazy(Implementation):
    """RangeSetLazy - int, add_range"""
    def set_up(self):
        self.ip_set = RangeSetLazy()

    def process_network(self, network):
        first_ip = int(network.network_address)
        last_ip = int(network.broadcast_address)
        self.ip_set.add_range(first_ip, last_ip)

    def total_unique_count(self):
        return self.ip_set.total_unique_count()


# ============================ MAIN CODE ===============================

# define a namedtuple for implementation metadata
ImplementationTuple = namedtuple('ImplementationTuple',
    ['i', 'class_', 'name', 'friendly_name', 'explanation', 'docs', 'source'])

# returns list and metadata of all implementations using reflection
def get_implementations():
    results = []
    i = 0
    for imp in Implementation.__subclasses__():
        i += 1           # i: 1-based index
        c = imp          # c: implementation class
        n = imp.__name__ # n: implementation name
        f = ''           # f: friendly name
        e = ''           # e: explanation
        d = imp.__doc__  # d: docstring
        dp = d.split(' - ', 1)
        if len(dp) == 2:
            f = dp[0] # friendly name from docstring
            e = dp[1] # explanation from docstring
        # s: source code fragment of implementation's process_network() method
        s = textwrap.dedent(''.join(inspect.getsourcelines(imp.process_network)[0][1:]))
        results.append(ImplementationTuple(i, c, n, f, e, d, s))
    return results

# list all implementations (command-line arg "-a")
def list_implementations(imp=None, table=None, verbose=False):
    imp = get_implementations() if not imp else imp
    if verbose:
        results = [(str(it.i) + ("\n\nx" if it.class_.dont_bench() else ""),
            it.name + "\n\n  " + ts.b(it.friendly_name),
            ts.d(it.explanation) + "\n\n" + it.source + ts.safe(U_X200B)) for it in imp]
        headers = [ts.b("#"), ts.b("Implementation Class"), ts.b("Description")]
    else:
        results = [(it.i, it.name, it.friendly_name, it.explanation) for it in imp]
        headers = ["#", "Implementation Class", "Name", "Description"]

    print("List of available implementations:\n")
    print(tabulate(results, headers, colalign=("right",),
        tablefmt=("heavy_grid" if verbose else "heavy_outline") if table is None else table))

# ======================================================================

# process input
def process_input(cidr_list, file_path, verbose):
    if cidr_list:
        return cidr_list.split()
    elif file_path:
        with open(file_path, 'r') as file:
            return file.read().splitlines()
    else:
        print("No input provided. Use '-h' or '--help' for usage information.")
        return None

# load ASN to CIDR mapping
def load_asn_to_cidr_mapping(asn_csv_path, verbose):
    start_time = gtime()
    start_mem = gmem()
    if verbose:
        print("Loading ASN-to-CIDR mappings...")

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

    end_time = gtime()
    end_mem = gmem()
    if verbose:
        print(f"\n  (memory: {fmem(start_mem)} -> {fmem(end_mem)}, diff: {fmem(end_mem-start_mem)})")
        print(f"  (time: {ftime(end_time - start_time)})\n")

    return asn_to_cidr

# get network ranges
def get_network_ranges(entry, asn_to_cidr):
    if entry.startswith("AS"):
        asn = int(entry[2:])
        if asn in asn_to_cidr:
            return asn_to_cidr[asn]
        else:
            raise ValueError(f"ASN '{entry}' not found in database.")
    else:
        return [ipaddress.ip_network(entry, strict=False)]

# ======================================================================

# wrapper to run implementation (command-line arg "-i X")
def run_implementation(implementation_class, cidr_ranges, asn_to_cidr, verbose=False, quiet=False, benchmark=False):
    start_time = gtime()
    start_mem = gmem()

    if not quiet or verbose:
        print(f"  (implementation: {implementation_class.__name__})")
        print(f"  (memory: {fmem(start_mem)})\n")

    implementation = implementation_class()
    implementation.set_up()

    i = total_ip_count = 0
    total_entries = len(cidr_ranges)
    i_len = len(str(total_entries))

    for entry in cidr_ranges:
        i += 1
        asn_entry = entry.startswith("AS")
        if not quiet and verbose:
            print(f"[{i:{i_len}}/{total_entries}] ", end="")
            if asn_entry:
                print(f"{entry} >")
        try:
            network_ranges = get_network_ranges(entry, asn_to_cidr)
            total_ranges = len(network_ranges)
            j_len = len(str(total_ranges))
            j = 0
            for network in network_ranges:
                j += 1
                total_ip_count += network.num_addresses
                implementation.process_network(network)
                if not quiet and verbose:
                    print(("    " if asn_entry else "") +
                          ("" if total_ranges == 1 else f"[{j:{j_len}}/{total_ranges}] ") +
                          f"CIDR: {network!s:>18} | IPs: {network.num_addresses:8} | "
                          f"From: {network.network_address!s:>15} | To: {network.broadcast_address!s:>15}")
                elif not quiet:
                    print(f" {network!s:>18} {'('+str(network.num_addresses):>9}): "
                          f"{network.network_address!s:>15} -> {network.broadcast_address!s:<15}") # ⟶
        except ValueError as e:
            if not quiet and verbose:
                print(f"    Skipping invalid entry '{entry}': {e}")

    total_unique_ips = implementation.total_unique_count()
    end_time = gtime()
    end_mem = gmem()

    if not quiet or verbose:
        print("" if quiet else "\n", end="")
        print(f"  (memory: {fmem(end_mem)}, diff: {fmem(end_mem-start_mem)})")
        print(f"  (time: {ftime(end_time - start_time)})\n")
    if not benchmark:
        #print("Summary:")
        print(f"  {total_ip_count} total IP addresses (including duplicates)")
        print(f"  {total_unique_ips} total unique IP addresses")
        print(f"    = {fip(total_unique_ips, TOTAL_IPV4_ADDRESSES)} of all possible IPv4 addresses")
        print(f"    = {fip(total_unique_ips)} of public IPv4 addresses (excl. reserved)")

    return total_ip_count, total_unique_ips, end_time - start_time, end_mem - start_mem

# ======================================================================

# wrapper to benchmark implementations (command-line arg "-b")
def benchmark_implementations(cidr_ranges, asn_to_cidr, imp, parent_process=False, table=None, verbose=False, quiet=False):
    print("Benchmarking implementations...\n")
    results = []
    max_imp = len(imp)
    i_len = len(str(max_imp))

    for it in imp:
        print(f" [{it.i:{i_len}}/{max_imp}] ({fmem(gmem())}) {it.name}: {it.friendly_name} ...", end="", flush=True)
        if it.class_.dont_bench():
            clear_line()
            continue
        if parent_process:
            _, total_unique_ips, time_taken, memory_used = run_implementation(
                it.class_, cidr_ranges, asn_to_cidr, verbose=False, quiet=True, benchmark=True)
        else: # execute each benchmark run in a child subprocess for better memory measurement and reclamation
            with concurrent.futures.ProcessPoolExecutor(max_workers=1) as executor:
                _, total_unique_ips, time_taken, memory_used = executor.submit(run_implementation,
                    it.class_, cidr_ranges, asn_to_cidr, verbose=False, quiet=True, benchmark=True).result()
        results.append((f"{it.i}", f"{ftime(time_taken)}", f"{total_unique_ips:,}", f"{fmem(memory_used)}", it.docs))
        clear_line()

    headers=["#", "Time Taken", "Unique IPs", "Memory Used", "Details"]
    print("Benchmark Results:\n")
    print(tabulate(results, headers, colalign=("right","right","right","right","left"),
        tablefmt="heavy_outline" if table is None else table))


# ============================== MAIN ==================================

def main():
    imp = get_implementations()
    prog = os.path.basename(sys.argv[0])

    print("====================================================\n"
          " CIDR and ASN list to number of unique IP addresses\n"
          "====================================================\n")

    parser = argparse.ArgumentParser(
        description="Calculates number of unique IPv4 addresses from list of CIDR ranges and/or ASN numbers.\n"
                    "  (and optionally benchmarks different implementations)",
        epilog="examples:\n"
               f"  {ts.B}-a                    {ts.E}{ts.D}list all available implementations{ts.E}\n"
               f"  {ts.B}-a -v                 {ts.E}{ts.D}list all available implementations with additional details{ts.E}\n"
               f"  {ts.B}-f 'cidr_asn_input_2.txt'{ts.E}\n"
               f"                        {ts.D}calculate number of unique IPs from input file using default implementation{ts.E}\n"
               f"  {ts.B}-l AS1 -v             {ts.E}{ts.D}detailed calculation for ASN number 1{ts.E}\n"
               f"  {ts.B}-l 18.26.0.0/15 -q    {ts.E}{ts.D}only summary results for one CIDR range{ts.E}\n"
               f"  {ts.B}-l 'AS1 AS2 AS3 1.1.1.1/24 4.4.4.4 4.4.4.0/28' -v{ts.E}\n"
               f"                        {ts.D}detailed calculation for list of ASN numbers, CIDR ranges and IP address{ts.E}\n"
               f"  {ts.B}-l 'AS3 128.30.0.0/16' -q -v{ts.E}\n"
               f"                        {ts.D}summary results and additinal memory information for ASN number and CIDR range{ts.E}\n"
               f"  {ts.B}-l 'AS2 AS3 128.30.0.0/16' -v -i 1{ts.E}\n"
               f"                        {ts.D}detailed calculation using implementation 1{ts.E}\n"
               f"  {ts.B}-l '1.1.1.1/12 2.0.0.0/8 128.30.0.0/16' -i 6{ts.E}\n"
               f"                        {ts.D}standard output for list of CIDR ranges using implementation 6{ts.E}\n"
               f"  {ts.B}-l '1.1.1.1/12 2.0.0.0/8 128.30.0.0/16' -b{ts.E}\n"
               f"                        {ts.D}benchmark implementations on list of CIDR ranges{ts.E}\n"
               f"  {ts.B}-l 'AS1 AS3 1.1.1.1/12 128.30.0.0/16' -b -p -v{ts.E}\n"
               f"                        {ts.D}benchmark on a list input without using child processes{ts.E}\n"
               f"  {ts.B}-f cidr_asn_input.txt -b -t simple{ts.E}\n"
               f"                        {ts.D}benchmark on a file input and provide results with 'simple' template{ts.E}\n"
               f"  {ts.B}-f cidr_asn_input_2.txt -b -p -t rounded_grid{ts.E}\n"
               f"                        {ts.D}benchmark on a file input and provide results with 'rounded_grid' template{ts.E}\n"
              ,
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        '-f', '--file', type=str,
        help="Path to a file containing CIDR ranges or ASN numbers (one per a line)."
    )
    parser.add_argument(
        '-l', '--list', type=str,
        help="Directly provide a space-separated list of CIDR ranges or ASN numbers."
    )
    parser.add_argument(
        '-i', '--implementation', type=int, choices=list(range(1,len(imp)+1)),
        help=f"Select a specific implementation to run (1-{len(imp)})."
    )
    parser.add_argument(
        '-b', '--benchmark', action='store_true',
        help="Run all implementations in benchmarking mode."
    )
    parser.add_argument(
        '-p', '--parent-process', action='store_true',
        help="Use parent process insted of child processes for benchmarking."
    )
    parser.add_argument(
        '-a', '--available', action='store_true',
        help="Show list of all available implementations."
    )
    parser.add_argument(
        '-t', '--table', type=str, metavar='FORMAT',
        help="Specify 'tabulate' table format for summary, i.e. 'simple', 'rounded_outline' or 'html'."
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

    if args.available:
        list_implementations(imp, args.table, args.verbose)
        return

    cidr_ranges = process_input(args.list, args.file, args.verbose)
    if not cidr_ranges:
        return

    asn_to_cidr = load_asn_to_cidr_mapping(ASN_CSV_PATH, args.verbose)

    if args.benchmark:
        # run benchmark
        benchmark_implementations(cidr_ranges, asn_to_cidr, imp, args.parent_process, args.table, args.verbose, args.quiet)
    elif args.implementation:
        # run specific implementation
        implementation_class = imp[args.implementation-1].class_
        run_implementation(implementation_class, cidr_ranges, asn_to_cidr, args.verbose, args.quiet)
    else:
        # run default implementation
        run_implementation(ImplementationRangeSetLazy, cidr_ranges, asn_to_cidr, args.verbose, args.quiet)

if __name__ == "__main__":
    main()

