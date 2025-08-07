import pyshark
from collections import defaultdict
import os
import sys

def analyze_tcp_handshakes(capture_file):
    # Get the directory of the PCAP file
    pcap_dir = os.path.dirname(capture_file)
    
    # Create the output file path
    output_file = os.path.join(pcap_dir, 'tcp_handshake_irtt_analysis.txt')
    
    # Redirect stdout to the file
    sys.stdout = open(output_file, 'w')

    # Open the capture file, filtering for TCP packets
    cap = pyshark.FileCapture(capture_file, display_filter="tcp")

    # Dictionary to store handshake states for each TCP stream
    handshakes = defaultdict(lambda: {'syn': False, 'syn_ack': False, 'ack': False, 'data': False, 'consecutive': True, 'irtt': None, 'syn_time': None})

    # Dictionary to store flow information for each TCP stream
    flows = defaultdict(lambda: {'src_ip': None, 'dst_ip': None, 'src_port': None, 'dst_port': None})

    # Dictionary to store packet sequence for each TCP stream
    packet_sequence = defaultdict(list)

    # Dictionary to store sequence numbers for each TCP stream
    seq_numbers = defaultdict(lambda: {'syn': None, 'syn_ack': None, 'ack': None})

    # Dictionary to store retransmission counts for SYN and SYN-ACK
    retransmissions = defaultdict(lambda: {'syn': 0, 'syn_ack': 0})

    # Iterate through all TCP packets
    for packet in cap:
        if 'TCP' in packet:
            tcp_layer = packet.tcp
            ip_layer = packet.ip
            stream_index = int(tcp_layer.stream)

            # Update flow information
            if flows[stream_index]['src_ip'] is None:
                flows[stream_index]['src_ip'] = ip_layer.src
                flows[stream_index]['dst_ip'] = ip_layer.dst
                flows[stream_index]['src_port'] = tcp_layer.srcport
                flows[stream_index]['dst_port'] = tcp_layer.dstport

            flags = int(tcp_layer.flags, 16)
            seq_num = int(tcp_layer.seq)

            # Check for SYN flag (0x02)
            if flags == 0x02:
                if not handshakes[stream_index]['syn']:
                    handshakes[stream_index]['syn'] = True
                    packet_sequence[stream_index].append('SYN')
                    handshakes[stream_index]['syn_time'] = float(packet.sniff_timestamp)
                    seq_numbers[stream_index]['syn'] = seq_num
                else:
                    retransmissions[stream_index]['syn'] += 1

            # Check for SYN-ACK flags (0x12)
            elif flags == 0x12:
                if not handshakes[stream_index]['syn_ack']:
                    handshakes[stream_index]['syn_ack'] = True
                    packet_sequence[stream_index].append('SYN-ACK')
                    seq_numbers[stream_index]['syn_ack'] = seq_num
                    # Calculate iRTT
                    if handshakes[stream_index]['syn_time'] is not None:
                        handshakes[stream_index]['irtt'] = float(packet.sniff_timestamp) - handshakes[stream_index]['syn_time']
                else:
                    retransmissions[stream_index]['syn_ack'] += 1

            # Check for ACK flag (0x10) (only if SYN and SYN-ACK have been seen)
            elif flags == 0x10 and handshakes[stream_index]['syn'] and handshakes[stream_index]['syn_ack']:
                if not handshakes[stream_index]['ack']:
                    handshakes[stream_index]['ack'] = True
                    packet_sequence[stream_index].append('ACK')
                    seq_numbers[stream_index]['ack'] = seq_num

            # Check for data packets (non-zero payload)
            if int(tcp_layer.len) > 0:
                handshakes[stream_index]['data'] = True
                if 'DATA' not in packet_sequence[stream_index]:
                    packet_sequence[stream_index].append('DATA')

    # Count flows with SYN and/or SYN-ACK
    relevant_flows = sum(1 for handshake in handshakes.values() if handshake['syn'] or handshake['syn_ack'])

    # Check if handshake packets are consecutive
    for stream_index, sequence in packet_sequence.items():
        if 'SYN' in sequence and 'SYN-ACK' in sequence and 'ACK' in sequence:
            syn_index = sequence.index('SYN')
            syn_ack_index = sequence.index('SYN-ACK')
            ack_index = sequence.index('ACK')
            if not (syn_index < syn_ack_index < ack_index and syn_ack_index == syn_index + 1 and ack_index == syn_ack_index + 1):
                handshakes[stream_index]['consecutive'] = False

    # Calculate summary statistics
    total_tcp_flows = len(handshakes)
    successful_handshakes = sum(1 for handshake in handshakes.values() if handshake['syn'] and handshake['syn_ack'] and handshake['ack'] and handshake['consecutive'])
    failed_handshakes = sum(1 for handshake in handshakes.values() if handshake['syn'] or handshake['syn_ack'] or handshake['ack']) - successful_handshakes
    data_only_flows = sum(1 for handshake in handshakes.values() if not handshake['syn'] and not handshake['syn_ack'] and handshake['data'])

    # Print summary
    print("TCP 3-Way Handshake and iRTT Analysis Summary:")
    print(f"Total TCP flows (based on TCP Stream Index): {total_tcp_flows}")
    print(f"Total TCP flows with SYN or SYN-ACK: {relevant_flows}")
    print(f"Successful handshakes: {successful_handshakes}")
    print(f"Failed handshakes: {failed_handshakes}")
    print(f"Data-only flows (handshake not captured): {data_only_flows}")

    print("\nDetailed Analysis:")
    for stream_index, handshake in handshakes.items():
        if handshake['syn'] or handshake['syn_ack'] or handshake['data']:  # Include data-only flows
            print(f"\nTCP Stream Index: {stream_index}")
            print(f"Handshake State:")
            print(f"  SYN seen: {'Yes' if handshake['syn'] else 'No'}")
            print(f"  SYN-ACK seen: {'Yes' if handshake['syn_ack'] else 'No'}")
            print(f"  ACK seen: {'Yes' if handshake['ack'] else 'No'}")
            
            if not handshake['syn'] and not handshake['syn_ack'] and handshake['data']:
                print("  Note: Data flow captured without SYN and SYN-ACK. Handshake might have occurred before capture started.")
                continue

            successful = handshake['syn'] and handshake['syn_ack'] and handshake['ack'] and handshake['consecutive']
            print(f"Successful Handshake: {'Yes' if successful else 'No'}")
            
            if not successful:
                if retransmissions[stream_index]['syn'] >= 8:
                    print("  Reason: SYN Retry Timeout (8 or more retransmissions)")
                elif retransmissions[stream_index]['syn_ack'] >= 8:
                    print("  Reason: SYN-ACK Retry Timeout (8 or more retransmissions)")
                elif not handshake['syn']:
                    print(f"  Reason: Missing SYN in 3-way handshake")
                elif not handshake['syn_ack']:
                    print(f"  Reason: Missing SYN-ACK in 3-way handshake")
                elif not handshake['ack']:
                    print(f"  Reason: Missing ACK in 3-way handshake")
                elif not handshake['consecutive']:
                    print(f"  Reason: Handshake packets not consecutive")
                
                if handshake['data']:
                    print("  Note: Data packets observed despite incomplete handshake")
            
            if handshake['irtt'] is not None:
                print(f"  Estimated iRTT: {handshake['irtt']:.6f} seconds")
            else:
                print("  Estimated iRTT: Not available")
            
            flow = flows[stream_index]
            print(f"Flow Information:")
            print(f"  Source IP:Port - {flow['src_ip']}:{flow['src_port']}")
            print(f"  Destination IP:Port - {flow['dst_ip']}:{flow['dst_port']}")

    # Close the capture file
    cap.close()

    # Close the output file
    sys.stdout.close()

    # Reset stdout to its default value
    sys.stdout = sys.__stdout__

    print(f"Analysis complete. Results written to {output_file}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python tcp_handshake_irtt_analysis_v2.py <path_to_pcap_file>")
        sys.exit(1)

    capture_file_path = sys.argv[1]

    if not os.path.exists(capture_file_path):
        print(f"Error: The file '{capture_file_path}' does not exist.")
        sys.exit(1)

    # Run the analysis
    analyze_tcp_handshakes(capture_file_path)
