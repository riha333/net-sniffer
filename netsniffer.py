from scapy.all import sniff
import subprocess

def sniff_packets():
    while True:
        # Display available network interfaces
        display_interfaces()

        # Prompt the user to select an interface
        interface = input("Select interface to sniff on: ")

        # Check if the selected interface exists
        if not is_valid_interface(interface):
            print(f"Error: Interface {interface} not found. Please try again.")
            continue

        # User inputs for packet limit and protocol filter
        limit = int(input("Enter number of packets to capture (0 for no limit): "))
        protocol = input("Filter by protocol? (Y/N): ").strip().lower()

        filter_expr = ""
        if protocol == "y":
            filter_expr = input("Specify protocol: ")

        # Start sniffing based on user input
        sniff_params = {'iface': interface, 'prn': show_packet, 'count': limit if limit else 0, 'filter': filter_expr}
        sniff(**{key: value for key, value in sniff_params.items() if value})

        # Option to exit the program
        if input("Exit? (Y/N): ").strip().lower() == "y":
            break

def show_packet(packet):
    packet.show()  # Show packet details

def display_interfaces():
    try:
        result = subprocess.run(['ip', 'link'], capture_output=True, text=True, check=True)
        print(result.stdout)
        interfaces = [line.split(":")[1].strip() for line in result.stdout.splitlines() if ":" in line]
        print("\nAvailable interfaces:", interfaces)
    except subprocess.CalledProcessError as e:
        print(f"Error: {e.stderr}")

def is_valid_interface(interface):
    """ Check if the interface exists on the system """
    result = subprocess.run(['ip', 'link'], capture_output=True, text=True, check=True)
    interfaces = [line.split(":")[1].strip() for line in result.stdout.splitlines() if ":" in line]
    return interface in interfaces

if __name__ == "__main__":
    sniff_packets()
