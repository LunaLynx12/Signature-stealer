import struct
import io

def gather_file_info(binary_path):
    """Parse PE file headers and return metadata dictionary"""
    try:
        with open(binary_path, 'rb') as binary:
            # DOS Header
            binary.seek(0x3C)
            pe_offset = struct.unpack('<I', binary.read(4))[0]
            
            # PE Header
            binary.seek(pe_offset)
            pe_signature = binary.read(4)
            if pe_signature != b'PE\0\0':
                raise ValueError("Invalid PE signature")
            
            # COFF Header
            machine_type = struct.unpack('<H', binary.read(2))[0]
            num_sections = struct.unpack('<H', binary.read(2))[0]
            timestamp = struct.unpack('<I', binary.read(4))[0]
            binary.seek(12, io.SEEK_CUR)  # Skip pointer to symbol table and number of symbols
            
            # Optional Header
            size_of_opt_header = struct.unpack('<H', binary.read(2))[0]
            magic = struct.unpack('<H', binary.read(2))[0]
            
            # Standard Fields
            binary.seek(6, io.SEEK_CUR)  # Skip linker version and size of code
            binary.seek(4, io.SEEK_CUR)  # Skip size of initialized data and uninitialized data
            entry_point = struct.unpack('<I', binary.read(4))[0]
            binary.seek(4, io.SEEK_CUR)  # Skip base of code
            
            # Initialize image_base with default value
            image_base = 0
            
            # Windows-Specific Fields - Handle known magic numbers
            if magic == 0x10b:  # PE32
                base_of_data = struct.unpack('<I', binary.read(4))[0]
                image_base = struct.unpack('<I', binary.read(4))[0]
                optional_header_size = 224  # Typical PE32 optional header size
            elif magic == 0x20b:  # PE32+
                image_base = struct.unpack('<Q', binary.read(8))[0]
                optional_header_size = 240  # Typical PE32+ optional header size
            else:
                # For unknown magic numbers, attempt to proceed with defaults
                print(f"[!] Warning: Unknown magic number 0x{magic:04x}, attempting to proceed")
                # Try to determine if it's 32 or 64-bit by machine type
                if machine_type in (0x8664, 0x0200):  # x64 or IA64
                    image_base = struct.unpack('<Q', binary.read(8))[0]
                    optional_header_size = 240
                else:
                    binary.read(4)  # Skip what would be base_of_data in PE32
                    image_base = struct.unpack('<I', binary.read(4))[0]
                    optional_header_size = 224
            
            # Calculate position of Data Directories
            data_dir_offset = pe_offset + 24 + optional_header_size - 128
            
            # Seek to SizeOfImage (should be at consistent offset regardless of magic)
            binary.seek(pe_offset + 24 + 56)  # Standard offset to SizeOfImage
            size_of_image = struct.unpack('<I', binary.read(4))[0]
            
            # Seek to Certificate Table in Data Directories
            binary.seek(data_dir_offset + 128)  # Certificate table is last entry
            cert_rva = struct.unpack('<I', binary.read(4))[0]
            cert_size = struct.unpack('<I', binary.read(4))[0]

        return {
            'PEOffset': pe_offset,
            'MachineType': machine_type,
            'NumberOfSections': num_sections,
            'TimeDateStamp': timestamp,
            'SizeOfOptHeader': size_of_opt_header,
            'Magic': magic,
            'EntryPoint': entry_point,
            'ImageBase': image_base,
            'SizeOfImage': size_of_image,
            'CertRVA': cert_rva,
            'CertSize': cert_size
        }
    except Exception as e:
        raise Exception(f"Error analyzing PE file: {str(e)}")