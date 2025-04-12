import struct
import io
import sys
import json
import logging

logging.basicConfig(level=logging.INFO)

def read_at_offset(binary, offset, fmt):
    binary.seek(offset)
    size = struct.calcsize(fmt)
    return struct.unpack(fmt, binary.read(size))

def parse_dos_header(binary):
    binary.seek(0x3C)
    pe_offset = struct.unpack('<I', binary.read(4))[0]
    return pe_offset

def parse_pe_header(binary, pe_offset):
    binary.seek(pe_offset)
    signature = binary.read(4)
    if signature != b'PE\0\0':
        raise ValueError("Invalid PE signature")

    machine_type, num_sections, timestamp = struct.unpack('<HHI', binary.read(8))
    binary.seek(12, io.SEEK_CUR)  # skip symbol table info
    size_of_opt_header = struct.unpack('<H', binary.read(2))[0]

    return machine_type, num_sections, timestamp, size_of_opt_header

def parse_optional_header(binary, pe_offset, machine_type):
    binary.seek(pe_offset + 24)
    magic = struct.unpack('<H', binary.read(2))[0]

    binary.seek(6, io.SEEK_CUR)  # skip linker version and size of code
    binary.seek(4, io.SEEK_CUR)  # skip initialized/uninitialized data
    entry_point = struct.unpack('<I', binary.read(4))[0]
    binary.seek(4, io.SEEK_CUR)  # skip base of code

    image_base = 0
    if magic == 0x10b:  # PE32
        binary.seek(4, io.SEEK_CUR)  # base_of_data
        image_base = struct.unpack('<I', binary.read(4))[0]
        optional_header_size = 224
    elif magic == 0x20b:  # PE32+
        image_base = struct.unpack('<Q', binary.read(8))[0]
        optional_header_size = 240
    else:
        logging.warning(f"[!] Unknown magic number 0x{magic:04x}, proceeding with fallback")
        if machine_type in (0x8664, 0x0200):  # x64 or IA64
            image_base = struct.unpack('<Q', binary.read(8))[0]
            optional_header_size = 240
        else:
            binary.read(4)  # skip base_of_data
            image_base = struct.unpack('<I', binary.read(4))[0]
            optional_header_size = 224

    return magic, entry_point, image_base, optional_header_size

def parse_data_directories(binary, pe_offset, optional_header_size):
    size_of_image_offset = pe_offset + 24 + 56
    binary.seek(size_of_image_offset)
    size_of_image = struct.unpack('<I', binary.read(4))[0]

    data_dir_offset = pe_offset + 24 + optional_header_size - 128
    binary.seek(data_dir_offset + 128)  # Certificate Table
    cert_rva, cert_size = struct.unpack('<II', binary.read(8))

    return size_of_image, cert_rva, cert_size

def gather_file_info(binary_path):
    try:
        with open(binary_path, 'rb') as binary:
            pe_offset = parse_dos_header(binary)
            machine_type, num_sections, timestamp, size_of_opt_header = parse_pe_header(binary, pe_offset)
            magic, entry_point, image_base, opt_header_size = parse_optional_header(binary, pe_offset, machine_type)
            size_of_image, cert_rva, cert_size = parse_data_directories(binary, pe_offset, opt_header_size)

            return {
                'PEOffset': pe_offset,
                'MachineType': f"0x{machine_type:04x}",
                'Arch': 'x64' if machine_type in (0x8664, 0x0200) else 'x86',
                'NumberOfSections': num_sections,
                'TimeDateStamp': timestamp,
                'SizeOfOptHeader': size_of_opt_header,
                'Magic': f"0x{magic:04x}",
                'EntryPoint': f"0x{entry_point:08x}",
                'ImageBase': f"0x{image_base:x}",
                'SizeOfImage': size_of_image,
                'CertRVA': cert_rva if cert_size else None,
                'CertSize': cert_size
            }
    except FileNotFoundError:
        raise Exception(f"File '{binary_path}' not found.")
    except struct.error as e:
        raise Exception(f"Struct unpacking error: {e}")
    except Exception as e:
        raise Exception(f"Error analyzing PE file: {str(e)}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python gather_file_info.py <binary_path>")
        sys.exit(1)
    info = gather_file_info(sys.argv[1])
    print(json.dumps(info, indent=4))
