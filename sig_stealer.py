from pe_analyzer import gather_file_info
import struct
import io
import os

def extract_certificate_only(binary_path):
    """Extract only the X.509 certificate portion from the signature"""
    sig_data = extract_complete_signature(binary_path)
    if not sig_data:
        return None
    
    # The certificate starts after the WIN_CERTIFICATE header (8 bytes) and PKCS7 header (varies)
    # This is a simplified approach - real implementation should properly parse PKCS7 structure
    try:
        # Skip WIN_CERTIFICATE header (8 bytes)
        pkcs7_data = sig_data[8:]
        
        # Find the start of the actual certificate (OID for PKCS7 signedData)
        cert_start = pkcs7_data.find(b'\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02')  # PKCS7 signedData OID
        if cert_start == -1:
            return None
            
        # This is a simplified extraction - a proper implementation would parse ASN.1 structure
        return pkcs7_data[cert_start:]
    except Exception as e:
        print(f"[!] Error parsing certificate: {e}")
        return None

def extract_complete_signature(binary_path):
    """Extract complete Authenticode signature including all headers"""
    try:
        with open(binary_path, 'rb') as f:
            # Get PE header offset
            f.seek(0x3C)
            pe_offset = struct.unpack('<I', f.read(4))[0]
            
            # Find the certificate table entry
            f.seek(pe_offset + 152 if os.path.getsize(binary_path) > pe_offset + 156 else 0)
            cert_rva, cert_size = struct.unpack('<II', f.read(8))
            
            if cert_size == 0:
                # Fallback: Check for appended signature at EOF
                f.seek(-8, 2)
                cert_offset, cert_size = struct.unpack('<II', f.read(8))
                if cert_size == 0 or cert_offset + cert_size > os.path.getsize(binary_path):
                    return None
                f.seek(cert_offset)
                return f.read(cert_size)
            
            # Standard extraction from certificate table
            f.seek(cert_rva)
            return f.read(cert_size)
    except Exception as e:
        print(f"[!] Error extracting signature: {e}")
        return None

# Update the existing functions to use these new ones
def extract_certificate(binary_path):
    """Legacy function - now uses extract_certificate_only"""
    return extract_certificate_only(binary_path)

def inject_certificate(target_binary, cert_data):
    """Inject certificate into target PE file (appends to EOF and updates headers)"""
    pe_info = gather_file_info(target_binary)
    
    try:
        with open(target_binary, 'r+b') as f:
            # Append certificate to end of file
            f.seek(0, io.SEEK_END)
            cert_offset = f.tell()
            f.write(cert_data)
            
            # Update certificate table in Optional Header
            cert_table_offset = pe_info['PEOffset'] + 152  # IMAGE_DIRECTORY_ENTRY_SECURITY
            f.seek(cert_table_offset)
            f.write(struct.pack('<I', cert_offset))  # CertRVA (raw offset in this case)
            f.write(struct.pack('<I', len(cert_data)))  # CertSize
            
            print(f"[+] Certificate injected at offset 0x{cert_offset:x}")
            return True
    except Exception as e:
        print(f"[!] Error injecting certificate: {e}")
        return False

def steal_and_inject_signature(source_exe, target_exe):
    """Copy complete signature from one binary to another"""
    sig_data = extract_complete_signature(source_exe)
    if not sig_data:
        print("[!] No signature found in source file")
        return False
    
    if not inject_certificate(target_exe, sig_data):
        return False
    
    print("[!] Warning: Signature mismatch will trigger AV!")
    return True