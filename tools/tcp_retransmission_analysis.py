import pyshark
from collections import defaultdict
import os
import sys

def analyze_tcp_flows(capture_file):
    # Get the directory of the PCAP file
    pcap_dir = os.path.dirname(capture_file)
    
    # Create the output file path
    output_file = os.path.join(pcap_dir, 'tcp_retransmission_analysis.txt')
    
    # Redirect stdout to the file
    sys.stdout = open(output_file, 'w')

    # Open the capture file, explicitly filtering for TCP
    cap = pyshark.FileCapture(capture_file, display_filter="tcp and not udp")

    # Initialize flow dictionary
    flows = defaultdict(lambda: {
        'total_packets': 0,
        'retransmissions': 0,
        'fast_retransmissions': 0,
        'out_of_order': 0,
        'resets': 0,
        'src_ip': set(),
        'dst_ip': set(),
        'src_port': set(),
        'dst_port': set()
    })

    # Iterate through all TCP packets
    for packet in cap:
        if 'TCP' in packet:
            tcp_layer = packet.tcp
            ip_layer = packet.ip
            
            # Use TCP stream index as the flow identifier
            flow_id = int(tcp_layer.stream)
            
            # Increment total packets for this flow
            flows[flow_id]['total_packets'] += 1
            
            # Add IP addresses and ports to the sets
            flows[flow_id]['src_ip'].add(ip_layer.src)
            flows[flow_id]['dst_ip'].add(ip_layer.dst)
            flows[flow_id]['src_port'].add(tcp_layer.srcport)
            flows[flow_id]['dst_port'].add(tcp_layer.dstport)
            
            # Check for TCP retransmissions
            if hasattr(tcp_layer, 'analysis_retransmission'):
                flows[flow_id]['retransmissions'] += 1
            
            # Check for TCP fast retransmissions
            if hasattr(tcp_layer, 'analysis_fast_retransmission'):
                flows[flow_id]['fast_retransmissions'] += 1
            
            # Check for out-of-order packets
            if hasattr(tcp_layer, 'analysis_out_of_order'):
                flows[flow_id]['out_of_order'] += 1
            
            # Check for TCP Resets
            if int(tcp_layer.flags, 16) & 0x04:  # Check if RST flag is set
                flows[flow_id]['resets'] += 1

    # Filter flows with non-zero values (except total_packets)
    interesting_flows = {
        flow_id: stats for flow_id, stats in flows.items()
        if any(value != 0 for key, value in stats.items() if key not in ['total_packets', 'src_ip', 'dst_ip', 'src_port', 'dst_port'])
    }

    # Print summary
    print("TCP Retransmission Analysis Summary:")
    print(f"Total number of TCP flows: {len(flows)}")
    print(f"Number of TCP flows with non-zero metrics: {len(interesting_flows)}")

    # Print detailed results
    print("\nDetailed TCP flow information:")
    for flow_id, stats in interesting_flows.items():
        print(f"\nTCP Flow (Stream Index): {flow_id}")
        print(f"  IPs involved: {stats['src_ip']} <-> {stats['dst_ip']}")
        print(f"  Ports involved: {stats['src_port']} <-> {stats['dst_port']}")
        print(f"  Total packets: {stats['total_packets']}")
        if stats['retransmissions'] > 0:
            print(f"  TCP Retransmissions: {stats['retransmissions']}")
        if stats['fast_retransmissions'] > 0:
            print(f"  TCP Fast Retransmissions: {stats['fast_retransmissions']}")
        if stats['out_of_order'] > 0:
            print(f"  Out-of-order packets: {stats['out_of_order']}")
        if stats['resets'] > 0:
            print(f"  TCP Resets: {stats['resets']}")

    # Close the capture file
    cap.close()

    # Close the output file
    sys.stdout.close()

    # Reset stdout to its default value
    sys.stdout = sys.__stdout__

    print(f"Analysis complete. Results written to {output_file}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python tcp_retransmission_analysis_v2.py <path_to_pcap_file>")
        sys.exit(1)

    capture_file_path = sys.argv[1]

    if not os.path.exists(capture_file_path):
        print(f"Error: The file '{capture_file_path}' does not exist.")
        sys.exit(1)

    # Run the analysis
    analyze_tcp_flows(capture_file_path)
