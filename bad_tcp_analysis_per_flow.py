import pyshark
from collections import defaultdict
import os
import sys

def analyze_tcp_packets_per_flow(capture_file):
    # Get the directory of the PCAP file
    pcap_dir = os.path.dirname(capture_file)
    
    # Create the output file path
    output_file = os.path.join(pcap_dir, 'bad_tcp_analysis_per_flow.txt')
    
    # Redirect stdout to the file
    sys.stdout = open(output_file, 'w')

    # Open the capture file
    cap = pyshark.FileCapture(capture_file, display_filter="tcp")

    # Initialize flow dictionary
    flows = defaultdict(lambda: {
        'total_packets': 0, 
        'bad_tcp_packets': 0,
        'src_ip': None,
        'dst_ip': None,
        'src_port': None,
        'dst_port': None
    })

    # Iterate through all TCP packets
    for packet in cap:
        if 'TCP' in packet and 'IP' in packet:
            tcp_layer = packet.tcp
            ip_layer = packet.ip
            stream_index = int(tcp_layer.stream)
            
            flows[stream_index]['total_packets'] += 1
            
            # Store IP addresses and ports if not already set
            if flows[stream_index]['src_ip'] is None:
                flows[stream_index]['src_ip'] = ip_layer.src
                flows[stream_index]['dst_ip'] = ip_layer.dst
                flows[stream_index]['src_port'] = tcp_layer.srcport
                flows[stream_index]['dst_port'] = tcp_layer.dstport
            
            # Apply the filter for bad TCP packets
            if hasattr(tcp_layer, 'analysis_flags') and not hasattr(tcp_layer, 'analysis_window_update'):
                flows[stream_index]['bad_tcp_packets'] += 1

    # Summary section
    total_flows = len(flows)
    flows_with_bad_tcp = sum(1 for flow in flows.values() if flow['bad_tcp_packets'] > 0)

    print("Summary:")
    print(f"Total number of TCP flows: {total_flows}")
    print(f"Number of TCP flows with bad TCP packets: {flows_with_bad_tcp}")
    print("\n")  # Add a blank line for better readability

    # Print results for flows with non-zero bad TCP packets
    print("TCP Flows with Bad TCP Packets:")
    for stream_index, flow_data in flows.items():
        total_packets = flow_data['total_packets']
        bad_tcp_packets = flow_data['bad_tcp_packets']
        
        if bad_tcp_packets > 0:
            bad_tcp_percentage = (bad_tcp_packets / total_packets) * 100
            print(f"\nTCP Stream Index: {stream_index}")
            print(f"  Source: {flow_data['src_ip']}:{flow_data['src_port']}")
            print(f"  Destination: {flow_data['dst_ip']}:{flow_data['dst_port']}")
            print(f"  Total TCP packets: {total_packets}")
            print(f"  Bad TCP packets: {bad_tcp_packets}")
            print(f"  Percentage of bad TCP packets: {bad_tcp_percentage:.2f}%")

    # Close the capture file
    cap.close()

    # Close the output file
    sys.stdout.close()

    # Reset stdout to its default value
    sys.stdout = sys.__stdout__

    print(f"Analysis complete. Results written to {output_file}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python bad_tcp_analysis_per_flow_v2.py <path_to_capture_file>")
        sys.exit(1)

    capture_file_path = sys.argv[1]
    
    if not os.path.exists(capture_file_path):
        print(f"Error: The file '{capture_file_path}' does not exist.")
        sys.exit(1)

    # Run the analysis
    analyze_tcp_packets_per_flow(capture_file_path)