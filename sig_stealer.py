from pe_analyzer import gather_file_info
import struct
import io

def extract_certificate(binary_path):
    """Properly extract Authenticode signature from PE file"""
    try:
        with open(binary_path, 'rb') as f:
            # Get PE header offset
            f.seek(0x3C)
            pe_offset = struct.unpack('<I', f.read(4))[0]
            
            # Find the certificate table location in the file (not memory)
            f.seek(pe_offset + 152)  # Offset to Certificate Table entry in Optional Header
            cert_rva = struct.unpack('<I', f.read(4))[0]
            cert_size = struct.unpack('<I', f.read(4))[0]
            
            if cert_size == 0:
                # Alternative method - look for signature at end of file
                f.seek(-8, 2)  # Go to last 8 bytes of file
                cert_offset = struct.unpack('<I', f.read(4))[0]
                cert_size = struct.unpack('<I', f.read(4))[0]
                
                if cert_size == 0 or cert_offset == 0:
                    return None
                
                f.seek(cert_offset)
                return f.read(cert_size)
            
            # Standard method - read from certificate table
            f.seek(cert_rva)
            return f.read(cert_size)
    except Exception as e:
        print(f"Error extracting certificate: {e}")
        return None

def inject_certificate(target_binary, cert_data):
    """Inject certificate into target PE file"""
    pe_info = gather_file_info(target_binary)
    
    with open(target_binary, 'r+b') as f:
        # Append certificate to end of file
        f.seek(0, io.SEEK_END)
        cert_offset = f.tell()
        
        # Write certificate data
        f.write(cert_data)
        
        # Update certificate table in headers
        cert_table_offset = pe_info['PEOffset'] + 24 + 128
        if pe_info['Magic'] == 0x20b:  # PE32+
            cert_table_offset = pe_info['PEOffset'] + 24 + 144
        
        f.seek(cert_table_offset)
        f.write(struct.pack('<I', cert_offset))  # CertRVA
        f.write(struct.pack('<I', len(cert_data)))  # CertSize

        