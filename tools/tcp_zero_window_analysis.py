import pyshark
from collections import defaultdict
from datetime import datetime, timezone
import sys
import os

def epoch_to_utc(epoch_time):
    return datetime.fromtimestamp(epoch_time, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S.%f UTC')

def analyze_tcp_zero_window(capture_file):
    # Get the directory of the PCAP file
    pcap_dir = os.path.dirname(capture_file)
    
    # Create the output file path
    output_file = os.path.join(pcap_dir, 'tcp_zero_window_analysis.txt')
    
    # Redirect stdout to the file
    sys.stdout = open(output_file, 'w')

    # Open the capture file
    cap = pyshark.FileCapture(capture_file, display_filter="tcp")

    # Initialize flow dictionary
    flows = defaultdict(lambda: {
        'zero_window_events': [],
        'current_zero_window': None,
        'src_ip': None,
        'dst_ip': None,
        'src_port': None,
        'dst_port': None
    })

    # Iterate through all TCP packets
    for packet in cap:
        tcp_layer = packet.tcp
        ip_layer = packet.ip
        
        # Use TCP stream index as the flow identifier
        flow_id = int(tcp_layer.stream)
        
        # Update flow information if not set
        if flows[flow_id]['src_ip'] is None:
            flows[flow_id]['src_ip'] = ip_layer.src
            flows[flow_id]['dst_ip'] = ip_layer.dst
            flows[flow_id]['src_port'] = tcp_layer.srcport
            flows[flow_id]['dst_port'] = tcp_layer.dstport

        # Check for TCP Zero Window
        if int(tcp_layer.window_size) == 0:
            if flows[flow_id]['current_zero_window'] is None:
                flows[flow_id]['current_zero_window'] = {
                    'start_time': float(packet.sniff_timestamp),
                    'reporting_ip': ip_layer.src,
                }
        elif flows[flow_id]['current_zero_window'] is not None:
            # Check if this is a Window Update from the same IP that reported Zero Window
            if ip_layer.src == flows[flow_id]['current_zero_window']['reporting_ip'] and int(tcp_layer.window_size) > 0:
                # Zero window event has ended
                end_time = float(packet.sniff_timestamp)
                duration = end_time - flows[flow_id]['current_zero_window']['start_time']
                flows[flow_id]['zero_window_events'].append({
                    'start_time': flows[flow_id]['current_zero_window']['start_time'],
                    'end_time': end_time,
                    'duration': duration,
                    'reporting_ip': flows[flow_id]['current_zero_window']['reporting_ip']
                })
                flows[flow_id]['current_zero_window'] = None

    # Filter flows with zero-window events
    zero_window_flows = {k: v for k, v in flows.items() if v['zero_window_events']}

    # Print summary
    print("TCP Zero Window Analysis Summary:")
    print(f"Total number of TCP flows: {len(flows)}")
    print(f"Number of TCP flows with Zero Window events: {len(zero_window_flows)}")

    # Print detailed results
    print("\nDetailed Zero Window event information:")
    for flow_id, flow_data in zero_window_flows.items():
        print(f"\nTCP Stream Index: {flow_id}")
        print(f"  Flow: {flow_data['src_ip']}:{flow_data['src_port']} -> {flow_data['dst_ip']}:{flow_data['dst_port']}")
        print(f"  Number of Zero Window events: {len(flow_data['zero_window_events'])}")
        for i, event in enumerate(flow_data['zero_window_events'], 1):
            print(f"  Event {i}:")
            print(f"    Zero window event reported by: {event['reporting_ip']}")
            print(f"    Zero window event start time: {epoch_to_utc(event['start_time'])}")
            print(f"    Zero window event end time: {epoch_to_utc(event['end_time'])}")
            print(f"    Zero window event duration: {event['duration']:.6f} seconds")

    # Close the capture file
    cap.close()

    # Close the output file
    sys.stdout.close()

    # Reset stdout to its default value
    sys.stdout = sys.__stdout__

    print(f"Analysis complete. Results written to {output_file}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python tcp_zero_window_analysis_v2.py <path_to_pcap_file>")
        sys.exit(1)

    capture_file_path = sys.argv[1]

    if not os.path.exists(capture_file_path):
        print(f"Error: The file '{capture_file_path}' does not exist.")
        sys.exit(1)

    # Run the analysis
    analyze_tcp_zero_window(capture_file_path)
