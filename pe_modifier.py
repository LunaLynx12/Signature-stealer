import struct
from pe_analyzer import gather_file_info

def zero_certificate_table(binary_path):
    """Zero out the certificate table in PE headers"""
    pe_info = gather_file_info(binary_path)
    
    with open(binary_path, 'r+b') as f:
        # Calculate offset to certificate table in optional header
        cert_table_offset = pe_info['PEOffset'] + 24 + 128  # Adjust based on PE32/PE32+
        
        # For PE32+, the offset is different
        if pe_info['Magic'] == 0x20b:
            cert_table_offset = pe_info['PEOffset'] + 24 + 144
        
        f.seek(cert_table_offset)
        f.write(struct.pack('<I', 0))  # Set CertRVA to 0
        f.write(struct.pack('<I', 0))  # Set CertSize to 0

def set_timestamp(binary_path, new_timestamp):
    """Modify PE file timestamp"""
    pe_info = gather_file_info(binary_path)
    
    with open(binary_path, 'r+b') as f:
        timestamp_offset = pe_info['PEOffset'] + 8
        f.seek(timestamp_offset)
        f.write(struct.pack('<I', new_timestamp))