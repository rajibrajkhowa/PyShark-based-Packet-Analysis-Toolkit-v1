import pyshark
import os
import sys
from collections import defaultdict

def analyze_tls_handshakes(capture_file):
    pcap_dir = os.path.dirname(capture_file)
    output_file = os.path.join(pcap_dir, 'tls_v1_3_handshake_analysis.txt')
    
    with open(output_file, 'w') as f:
        sys.stdout = f
        
        print(f"Analyzing file: {capture_file}")
        
        try:
            cap = pyshark.FileCapture(capture_file, display_filter="tls.handshake.extensions.supported_version == 0x0304")
        except Exception as e:
            print(f"Error opening capture file: {e}")
            return

        # Dictionary to store TCP streams with TLS traffic
        tls_streams = defaultdict(lambda: {
            'client_ip': None,
            'server_ip': None,
            'handshake': {
                'Client Hello': False,
                'Server Hello': False,
                'Change Cipher Spec Server': False,
                'Change Cipher Spec Client': False,
            }
        })

        # Analyze TLS handshakes
        for packet in cap:
            if 'TLS' in packet and 'TCP' in packet:
                stream_index = int(packet.tcp.stream)
                handshake = tls_streams[stream_index]['handshake']

                if hasattr(packet.tls, 'handshake_type'):
                    handshake_types = packet.tls.handshake_type.all_fields

                    for field in handshake_types:
                        handshake_type = field.show

                        if handshake_type == '1':
                            handshake['Client Hello'] = True
                            tls_streams[stream_index]['client_ip'] = packet.ip.src
                        elif handshake_type == '2':
                            handshake['Server Hello'] = True
                            tls_streams[stream_index]['server_ip'] = packet.ip.src
                            # Check for Change Cipher Spec in the same packet
                            if hasattr(packet.tls, 'change_cipher_spec'):
                                handshake['Change Cipher Spec Server'] = True

                        # Check for Change Cipher Spec in the same packet
                        if hasattr(packet.tls, 'change_cipher_spec'):
                             handshake['Change Cipher Spec Client'] = True

        # Print summary
        total_streams = len(tls_streams)
        successful_handshakes = sum(1 for stream_data in tls_streams.values() if all(stream_data['handshake'].values()))

        print("TLS v1.3 Handshake Analysis Summary:")
        print(f"Total TLS v1.3 streams analyzed: {total_streams}")
        print(f"Successful TLS v1.3 handshakes: {successful_handshakes}")
        print(f"Incomplete TLS v1.3 handshakes: {total_streams - successful_handshakes}")

        # Print detailed results
        print("\nDetailed TLS v1.3 Handshake Analysis:")
        for stream_index, stream_data in tls_streams.items():
            print(f"\nTCP Stream Index: {stream_index}")
            print(f"Client IP: {stream_data['client_ip']}")
            print(f"Server IP: {stream_data['server_ip']}")
            print("TLS v1.3 Handshake Status:")
            for step, status in stream_data['handshake'].items():
                print(f"  {step}: {'Yes' if status else 'No'}")
            
            if all(stream_data['handshake'].values()):
                print("TLS v1.3 Handshake: Successful")
            else:
                print("TLS v1.3 Handshake: Incomplete")
                missing_steps = [step for step, status in stream_data['handshake'].items() if not status]
                print("Reason(s) for incomplete handshake:")
                for step in missing_steps:
                    print(f"  - Missing {step}")

        cap.close()

    sys.stdout = sys.__stdout__
    print(f"Analysis complete. Results written to {output_file}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python tls_v1_3_handshake_analysis_v2.py <path_to_pcap_file>")
        sys.exit(1)

    capture_file_path = sys.argv[1]

    if not os.path.exists(capture_file_path):
        print(f"Error: The file '{capture_file_path}' does not exist.")
        sys.exit(1)

    # Run the analysis
    analyze_tls_handshakes(capture_file_path)