import pyshark
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone

def epoch_to_utc(epoch_time):
    return datetime.fromtimestamp(float(epoch_time), tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S.%f UTC')

def analyze_tcp_retransmissions_recovery(capture_file):
    pcap_dir = os.path.dirname(capture_file)
    output_file = os.path.join(pcap_dir, 'tcp_retransmission_recovery_analysis.txt')

    cap = pyshark.FileCapture(capture_file, display_filter="tcp")

    flows = defaultdict(lambda: {
        'retransmissions': defaultdict(dict),
        'acks': defaultdict(list),
        'src_ip': set(),
        'dst_ip': set(),
        'src_port': set(),
        'dst_port': set()
    })

    for packet in cap:
        if 'TCP' in packet:
            tcp_layer = packet.tcp
            ip_layer = packet.ip
            stream_index = int(tcp_layer.stream)
            seq_num = int(tcp_layer.seq)
            next_seq = seq_num + int(tcp_layer.len)
            frame_number = int(packet.frame_info.number)
            
            flows[stream_index]['src_ip'].add(ip_layer.src)
            flows[stream_index]['dst_ip'].add(ip_layer.dst)
            flows[stream_index]['src_port'].add(tcp_layer.srcport)
            flows[stream_index]['dst_port'].add(tcp_layer.dstport)

            if hasattr(tcp_layer, 'analysis_retransmission') or hasattr(tcp_layer, 'analysis_fast_retransmission'):
                retrans_type = "Fast Retransmission" if hasattr(tcp_layer, 'analysis_fast_retransmission') else "Retransmission"
                if seq_num not in flows[stream_index]['retransmissions']:
                    flows[stream_index]['retransmissions'][seq_num] = {
                        'first_time': float(packet.sniff_timestamp),
                        'next_seq': next_seq,
                        'frame_number': frame_number,
                        'type': retrans_type
                    }

            ack_num = int(tcp_layer.ack)
            flows[stream_index]['acks'][ack_num].append((float(packet.sniff_timestamp), frame_number))

    with open(output_file, 'w') as f:
        f.write("TCP Retransmission Analysis:\n\n")
        for stream_index, flow in flows.items():
            if flow['retransmissions']:
                f.write(f"TCP Flow (Stream Index): {stream_index}\n")
                f.write(f"  IPs involved: {flow['src_ip']} <-> {flow['dst_ip']}\n")
                f.write(f"  Ports involved: {flow['src_port']} <-> {flow['dst_port']}\n")
                f.write(f"  Total retransmissions: {len(flow['retransmissions'])}\n")
                
                f.write("  Retransmitted Sequence Numbers:\n")
                for seq_num, retrans_info in flow['retransmissions'].items():
                    write_retransmission_info(f, seq_num, retrans_info, flow['acks'])
                
                f.write("\n")

    cap.close()
    return f"Analysis complete. Results written to {output_file}"

def write_retransmission_info(f, seq_num, retrans_info, acks):
    first_time = epoch_to_utc(retrans_info['first_time'])
    next_seq = retrans_info['next_seq']
    frame_number = retrans_info['frame_number']
    retrans_type = retrans_info['type']
    f.write(f"    Sequence Number: {seq_num}\n")
    f.write(f"      Expected Next Sequence Number: {next_seq}\n")
    f.write(f"      First {retrans_type} Time: {first_time}\n")
    f.write(f"      First {retrans_type} Frame Number: {frame_number}\n")
    
    if next_seq in acks and acks[next_seq]:
        ack_time, ack_frame = min(acks[next_seq], key=lambda x: x[0])  # Use the earliest ACK time
        ack_time_utc = epoch_to_utc(ack_time)
        recovery_time = ack_time - retrans_info['first_time']
        f.write(f"      ACK Time: {ack_time_utc}\n")
        f.write(f"      ACK Frame Number: {ack_frame}\n")
        f.write(f"      Recovery Time: {recovery_time:.6f} seconds\n")
    else:
        f.write("      ACK Time: Not observed\n")
        f.write("      ACK Frame Number: Not observed\n")
        f.write("      Recovery Time: Unable to calculate\n")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python tcp_retransmission_recovery_analysis.py <path_to_pcap_file>")
        sys.exit(1)

    capture_file_path = sys.argv[1]

    if not os.path.exists(capture_file_path):
        print(f"Error: The file '{capture_file_path}' does not exist.")
        sys.exit(1)

    result = analyze_tcp_retransmissions_recovery(capture_file_path)
    print(result)