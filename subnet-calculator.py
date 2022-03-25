import socket
import struct
import sys


def check_valid_subnet(ip_string):
    valid_subnets = ["255.255.255.255", "255.255.255.254", "255.255.255.252", "255.255.255.248", "255.255.255.240",
                     "255.255.255.224",
                     "255.255.255.192", "255.255.255.128", "255.255.255.0", "255.255.254.0", "255.255.252.0",
                     "255.255.248.0",
                     "255.255.240.0", "255.255.224.0", "255.255.192.0", "255.255.128.0", "255.255.0.0", "255.254.0.0",
                     "255.252.0.0",
                     "255.248.0.0", "255.240.0.0", "255.224.0.0", "255.192.0.0", "255.128.0.0", "255.0.0.0",
                     "254.0.0.0", "252.0.0.0",
                     "248.0.0.0", "240.0.0.0", "224.0.0.0", "192.0.0.0", "128.0.0.0", "0.0.0.0"]
    if ip_string in valid_subnets:
        return True
    else:
        print("Invalid Subnet! " + ip_string)
        return False


def get_ip_bytes(ip_string):
    try:
        ip_address = socket.inet_aton(ip_string)
        return ip_address
    except OSError:
        print("Invalid IP Address")
        exit()


def get_ip_class(ip_bytes):
    first_octet = ip_bytes[0]
    if 0 <= first_octet <= 127:
        return ["Class A", 24]
    elif 128 <= first_octet <= 191:
        return ["Class B", 16]
    elif 192 <= first_octet <= 223:
        return ["Class C", 8]
    else:
        return "Error in octet - " + str(first_octet)


def get_ip_binary_list(ip_bytes):
    binary_octets = []
    for byte in ip_bytes:
        binary_octets.append(bin(byte)[2:])
    return binary_octets


def convert_binary_list_to_string(bin_list):
    binary_string = ""
    for binary in bin_list:
        binary_string += str(binary).zfill(8) + '.'
    binary_string = binary_string[:-1]
    return binary_string


def get_borrow_bits(ip_string):
    return ip_string.count("0")


def get_wildcard_mask(subnet_address):
    wildcard_mask = []
    for octet in subnet_address:
        wildcard_mask.append(255 - octet)
    return wildcard_mask


def get_new_subnet_mask(subnet_address, borrowed_bits):
    subnet_binary = get_ip_binary_list(subnet_address)
    binary_long_string = ""
    for binary in subnet_binary:
        binary_long_string += str(bin(int(binary, 2))[2:]).zfill(8)

    first_zero = binary_long_string.find("0")
    new_binary_string = '1' * (first_zero - 1)
    new_binary_string = new_binary_string + '1' * borrowed_bits
    new_binary_string = new_binary_string + '0' * (len(binary_long_string) - len(new_binary_string))

    new_mask = socket.inet_ntoa(struct.pack('!L', int(new_binary_string, 2)))
    return new_mask


def get_least_sig_bit_value(subnet_mask_address):
    for octet in subnet_mask_address:
        if int(octet) != 255:
            binary = bin(octet)[2:]
            lsb = str(binary).rfind("1") + 1
            lsb = 8 - lsb
            return 2 ** lsb


def generate_subnet_list(ip_class, local_address, lsb_value):
    subnets = []
    if ip_class == "Class A":
        iteration_address = [local_address[0], 0, 0, 0,
                             local_address[0], lsb_value - 1, 0, 0]
        subnets.append(iteration_address)

        current_octet = 0
        while (current_octet + lsb_value) <= 255:
            current_octet += lsb_value
            subnets.append([local_address[0], current_octet, 0, 0,
                            local_address[0], current_octet + lsb_value - 1, 0, 0])

    elif ip_class == "Class B":
        iteration_address = [local_address[0], local_address[1], 0, 0,
                             local_address[0], local_address[1], lsb_value - 1, 0]
        subnets.append(iteration_address)

        current_octet = 0
        while (current_octet + lsb_value) <= 255:
            current_octet += lsb_value
            subnets.append([local_address[0], local_address[1], current_octet, 0,
                            local_address[0], local_address[1], current_octet + lsb_value - 1, 0])

    elif ip_class == "Class C":
        iteration_address = [local_address[0], local_address[1], local_address[2], 0,
                             local_address[0], local_address[1], local_address[2], lsb_value - 1]
        subnets.append(iteration_address)

        current_octet = 0
        while (current_octet + lsb_value) <= 255:
            current_octet += lsb_value
            subnets.append([local_address[0], local_address[1], local_address[2], current_octet,
                            local_address[0], local_address[1], local_address[2], current_octet + lsb_value - 1])

    else:
        return ["Unknown Address Class"]

    return subnets


def main(args):
    subnet_string = ""
    local_string = ""

    # Get subnet info
    subnet_address = get_ip_bytes(args[1])

    for byte in subnet_address:
        subnet_string = subnet_string + str(int(byte)) + "."
    subnet_string = subnet_string[:-1]

    valid_subnet = check_valid_subnet(subnet_string)
    if not valid_subnet:
        return

    # Get local address info
    local_address = get_ip_bytes(args[2])

    for byte in local_address:
        local_string = local_string + str(int(byte)) + "."
    local_string = local_string[:-1]

    # Get both addresses binary equivalent

    subnet_binary = get_ip_binary_list(subnet_address)
    subnet_binary_string = convert_binary_list_to_string(subnet_binary)

    local_binary = get_ip_binary_list(local_address)
    local_binary_string = convert_binary_list_to_string(local_binary)

    subnet_prefix = '/' + str(subnet_binary_string.count("1"))

    # Borrowed Bits Information

    borrowed_bits = get_borrow_bits(subnet_binary_string)
    possible_subnets = 2 ** borrowed_bits  # calculate possible subnets using 2^n where n is the borrowed bits

    ip_class_info = get_ip_class(local_address)
    ip_class = ip_class_info[0]
    available_host_bits = ip_class_info[1]
    remaining_host_bits = available_host_bits - borrowed_bits

    possible_hosts = (2 ** remaining_host_bits) - 2  # 2 reserved addresses for the broadcast and network

    # Wildcard Info

    wildcard = get_wildcard_mask(subnet_address)
    wildcard_string = '.'.join(map(str, wildcard))  # Convert to IP string

    # New Subnet Mask

    new_subnet_mask_string = get_new_subnet_mask(subnet_address, borrowed_bits)
    new_subnet_mask = get_ip_bytes(new_subnet_mask_string)
    new_subnet_binary = convert_binary_list_to_string(get_ip_binary_list(new_subnet_mask))

    # New Subnets

    lsb_value = get_least_sig_bit_value(subnet_address)
    subnet_list = generate_subnet_list(str(ip_class), local_address, lsb_value)

    # Print Info

    print("## IP INFO ##")
    print("Subnet Mask: " + str(subnet_string) + str(subnet_prefix))
    print("Validated Subnet: " + str(valid_subnet))
    print("Local IP: " + str(local_string))
    print("Local IP Class: " + str(ip_class))
    print("Wildcard Address: " + str(wildcard_string))
    print("\n## BINARY ##")
    print("Subnet IP Binary: " + str(subnet_binary_string))
    print("Local IP Binary: " + str(local_binary_string))
    print("\n## BIT CALCULATION ##")
    print("Borrowed Bits: " + str(borrowed_bits))
    print("Available Bits: " + str(available_host_bits))
    print("Remaining Bits: " + str(remaining_host_bits))
    print("\n## POSSIBLE HOSTS AND SUBNETS ##")
    print("Possible Subnets: " + str(possible_subnets))
    print("Possible Hosts Per Subnet: " + str(possible_hosts))
    print("\n## NEW SUBNET MASK ##")
    print("New Subnet Mask: " + str(new_subnet_mask_string))
    print("New Subnet Binary: " + str(new_subnet_binary))
    print("Least Significant Bit Value: " + str(lsb_value))
    print("\n## SUBNETS ##")
    for subnet_info in subnet_list:
        print("Start of subnet: " + '.'.join(map(str, subnet_info[0:4])), end="   ")
        print("Broadcast address: " + '.'.join(map(str, subnet_info[-4:])))


if __name__ == '__main__':
    if len(sys.argv) == 3:
        main(sys.argv)
    else:
        print("Usage: subnet-calculator [Subnet IP] [Local IP]")

# Resources
"""
https://d12vzecr6ihe4p.cloudfront.net/media/966010/wp-subnetting-an-ip-address.pdf

"""
