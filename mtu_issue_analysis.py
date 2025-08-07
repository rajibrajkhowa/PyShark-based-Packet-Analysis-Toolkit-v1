import pyshark
from collections import defaultdict
import os
import sys

def analyze_mtu_issues(capture_file):
    # Get the directory of the PCAP file
    pcap_dir = os.path.dirname(capture_file)
    
    # Create the output file path
    output_file = os.path.join(pcap_dir, 'mtu_issue_analysis.txt')
    
    # Redirect stdout to the file
    sys.stdout = open(output_file, 'w')

    # Open the capture file
    cap = pyshark.FileCapture(capture_file)

    # Initialize counters and dictionaries
    flows = defaultdict(lambda: {
        'large_packets': defaultdict(int),
        'sender_mss': None,
        'receiver_mss': None,
        'src_ip': None,
        'dst_ip': None,
        'src_port': None,
        'dst_port': None,
        'total_packets': 0,
        'fragmented_packets': 0,
        'small_df_packets': 0,  # New counter for small packets with DF set and PSH unset
        'large_df_packets_count': 0  # New counter for large packets with DF set
    })
    icmp_fragmentation_needed = []
    mtu_sizes = [1500, 1492, 1472, 1468, 1400]  # Common MTU sizes
    min_mss = 536  # Minimum MSS size

    # Iterate through all packets
    for packet in cap:
        if 'TCP' in packet and 'IP' in packet:
            tcp_layer = packet.tcp
            ip_layer = packet.ip
            stream_index = int(tcp_layer.stream)
            packet_length = int(ip_layer.len)
            tcp_payload_length = int(tcp_layer.len)
            
            # Update flow information
            flows[stream_index]['total_packets'] += 1
            if flows[stream_index]['src_ip'] is None:
                flows[stream_index]['src_ip'] = ip_layer.src
                flows[stream_index]['dst_ip'] = ip_layer.dst
                flows[stream_index]['src_port'] = tcp_layer.srcport
                flows[stream_index]['dst_port'] = tcp_layer.dstport

            # Check for SYN packets to estimate MSS
            if int(tcp_layer.flags, 16) & 0x02:  # SYN flag
                if hasattr(tcp_layer, 'options_mss_val'):
                    if flows[stream_index]['src_ip'] == ip_layer.src:
                        flows[stream_index]['sender_mss'] = int(tcp_layer.options_mss_val)
                    else:
                        flows[stream_index]['receiver_mss'] = int(tcp_layer.options_mss_val)
            
            # Check for large packets with DF bit set
            if packet_length >= 1400 and int(ip_layer.flags, 16) & 0x4000:  # 0x4000 is the DF flag
                flows[stream_index]['large_packets'][packet_length] += 1
                flows[stream_index]['large_df_packets_count'] = flows[stream_index].get('large_df_packets_count', 0) + 1

            # Check for fragmented packets
            if int(ip_layer.flags, 16) & 0x2000 or int(ip_layer.frag_offset) > 0:  # More fragments or non-zero fragment offset
                flows[stream_index]['fragmented_packets'] += 1

            # Check for small packets with DF bit set and PSH flag unset
            if (tcp_payload_length <= min_mss and 
                int(ip_layer.flags, 16) & 0x4000 and  # DF bit set
                not int(tcp_layer.flags, 16) & 0x08):  # PSH flag unset
                flows[stream_index]['small_df_packets'] += 1
        
        # Check for ICMP Fragmentation Needed messages
        if 'ICMP' in packet and int(packet.icmp.type) == 3 and int(packet.icmp.code) == 4:
            icmp_fragmentation_needed.append({
                'src': packet.ip.src,
                'dst': packet.ip.dst,
                'next_hop_mtu': packet.icmp.mtu if hasattr(packet.icmp, 'mtu') else 'Unknown'
            })

    # Close the capture file
    cap.close()

    # Print summary
    print("Summary:")
    flows_with_issues = sum(1 for flow in flows.values() if flow['large_packets'] or flow['fragmented_packets'] > 0 or flow['small_df_packets'] > 0)
    print(f"Total TCP flows analyzed: {len(flows)}")
    print(f"TCP flows with potential MTU issues: {flows_with_issues}")
    print(f"ICMP Fragmentation Needed messages: {len(icmp_fragmentation_needed)}")
    print("\n")  # Add a blank line for better readability

    # Print results
    print("MTU Issue Analysis by TCP Flow:")
    for stream_index, flow_data in flows.items():
        print(f"\nTCP Stream Index: {stream_index}")
        print(f"Source: {flow_data['src_ip']}:{flow_data['src_port']}")
        print(f"Destination: {flow_data['dst_ip']}:{flow_data['dst_port']}")
        print(f"Total Packets: {flow_data['total_packets']}")
        print(f"Fragmented Packets: {flow_data['fragmented_packets']}")
        print(f"Sender MSS: {flow_data['sender_mss'] if flow_data['sender_mss'] else 'Not detected'}")
        print(f"Receiver MSS: {flow_data['receiver_mss'] if flow_data['receiver_mss'] else 'Not detected'}")
        
        if flow_data['large_packets']:
            print("Large packets with DF bit set:")
            for size, count in sorted(flow_data['large_packets'].items()):
                print(f"  Size {size} bytes: {count} packets")
                for mtu in mtu_sizes:
                    if size > mtu:
                        print(f"    - May cause fragmentation on networks with MTU {mtu}")
            
            print("Potential MTU issues:")
            print("  - Large packets with DF bit set may cause fragmentation on some networks")
            print("  - Consider path MTU discovery or reducing packet sizes for this flow")
        else:
            print("No large packets with DF bit set detected for this flow")

        if flow_data['fragmented_packets'] > 0:
            print(f"Warning: {flow_data['fragmented_packets']} fragmented packets detected in this flow")
            print("  - This may indicate MTU issues or normal fragmentation")
        else:
            print("No fragmented packets detected in this flow")
            print("  - This suggests no MTU-related fragmentation issues for this flow")

        if flow_data['small_df_packets'] > 0:
            print(f"Warning: {flow_data['small_df_packets']} small packets (<=536 bytes) with DF bit set and PSH flag unset")
            print("  - This may indicate potential MTU issues or inefficient use of network resources")
        else:
            print("No small packets with DF bit set and PSH flag unset detected in this flow")
            print("  - This suggests efficient use of network resources for this flow")

    print("\nICMP Fragmentation Needed messages:")
    if icmp_fragmentation_needed:
        for msg in icmp_fragmentation_needed:
            print(f"  From {msg['src']} to {msg['dst']}, Next-hop MTU: {msg['next_hop_mtu']}")
    else:
        print("  No ICMP Fragmentation Needed messages found")

    # Close the output file
    sys.stdout.close()

    # Reset stdout to its default value
    sys.stdout = sys.__stdout__

    print(f"Analysis complete. Results written to {output_file}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python mtu_issue_analysis_v2.py <path_to_pcap_file>")
        sys.exit(1)

    capture_file_path = sys.argv[1]

    if not os.path.exists(capture_file_path):
        print(f"Error: The file '{capture_file_path}' does not exist.")
        sys.exit(1)

    # Run the analysis
    analyze_mtu_issues(capture_file_path)