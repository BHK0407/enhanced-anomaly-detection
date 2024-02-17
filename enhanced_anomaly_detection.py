from scapy.all import IP, TCP, UDP, Raw, sniff, get_if_list
from collections import Counter
import time
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging
import os

# Get the directory of the script
script_directory = os.path.dirname(os.path.abspath(__file__))

# Global variable for anomaly detection
port_anomalies = set()
traffic_threshold = 50  # Adjust the threshold based on my network's normal traffic volume

# Email configuration
email_config = {
    'smtp_server': 'smtp.example.com',
    'smtp_port': 587,
    'smtp_username': 'your_username',
    'smtp_password': 'your_password',
    'sender_email': 'your_sender_email@example.com',
    'recipient_email': 'your_recipient_email@example.com'
}

# Threat Intelligence - Known Malicious IPs
known_malicious_ips = ['1.2.3.4', '5.6.7.8']

# Logging configuration
log_file_path = os.path.join(script_directory, 'anomaly_detection.log')
logging.basicConfig(filename=log_file_path, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Create a logger
logger = logging.getLogger(__name__)


def send_email(subject, body):
    # Create the MIME object
    message = MIMEMultipart()
    message['From'] = email_config['sender_email']
    message['To'] = email_config['recipient_email']
    message['Subject'] = subject

    # Attach the body of the email
    message.attach(MIMEText(body, 'plain'))

    # Connect to the SMTP server and send the email
    with smtplib.SMTP(email_config['smtp_server'], email_config['smtp_port']) as server:
        server.starttls()  # Use TLS
        server.login(email_config['smtp_username'], email_config['smtp_password'])
        server.sendmail(email_config['sender_email'], email_config['recipient_email'], message.as_string())


def check_unusual_ports(packet):
    if TCP in packet:
        dst_port = packet[TCP].dport
        if dst_port > 10000:
            port_anomalies.add(f"Unusual high destination port: {dst_port}")
            logger.warning(f"Unusual high destination port: {dst_port}")


def check_high_traffic_volume(packet_counter):
    total_packets = sum(packet_counter.values())
    if total_packets > traffic_threshold:
        port_anomalies.add(f"High traffic volume detected: {total_packets}")
        logger.warning(f"High traffic volume detected: {total_packets}")


def signature_based_detection(packet):
    # Implement signature-based detection rules
    if is_malicious_pattern(packet):
        print(f"Signature-based threat detected!")
        logger.warning("Signature-based threat detected!")


def anomaly_based_detection(packet):
    # Implement anomaly-based detection rules
    if is_anomalous_behavior(packet):
        print(f"Anomaly-based threat detected!")
        logger.warning("Anomaly-based threat detected!")


def is_known_threat_signature(packet):
    # Check if the source IP is in the list of known malicious IPs
    return packet[IP].src in known_malicious_ips


def integrate_threat_intelligence(packet):
    # Implement logic to check against threat intelligence feeds
    return False  # Replace with implementation


def combined_detection(packet):
    # Implement combined detection logic
    if is_known_threat_signature(packet):
        signature_based_detection(packet)
        send_email("Known Threat Detected", "Signature-based threat detected!")
    elif is_anomalous_behavior(packet):
        anomaly_based_detection(packet)
        send_email("Anomaly Detected", "Anomaly-based threat detected!")
    else:
        print(f"No threats detected")


def is_malicious_pattern(packet):
    # Check if the packet is a TCP packet with payload
    if TCP in packet and Raw in packet:
        payload = packet[Raw].load.decode('utf-8', errors='ignore')

        # Define a malicious keyword or pattern to look for
        malicious_keyword = "malicious_pattern"

        # Check if the malicious keyword is present in the payload
        if malicious_keyword in payload:
            return True  # Malicious pattern detected
    return False  # No malicious pattern


def is_anomalous_behavior(packet):
    if TCP in packet and Raw in packet:
        payload_length = len(packet[Raw].load)
        return payload_length > 100
    return False


def packet_handler(packet):
    # Extract and print information from the packet
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        print(f"Source IP: {src_ip}, Destination IP: {dst_ip}")

    if TCP in packet:
        check_unusual_ports(packet)
        signature_based_detection(packet)
        anomaly_based_detection(packet)
        combined_detection(packet)

    if UDP in packet:
        check_unusual_ports(packet)

    # Display the raw packet summary
    print(packet.summary())


def start_sniffing(interface=None, count=10):
    iface = interface if interface in get_if_list() else None
    packet_counter = Counter()

    def packet_counter_handler(packet):
        packet_counter['total'] += 1
        packet_handler(packet)

    sniff(iface=iface, prn=packet_counter_handler, count=count)

    # After sniffing, check for anomalies
    check_high_traffic_volume(packet_counter)
    if port_anomalies:
        print("Anomalies detected:")
        for anomaly in port_anomalies:
            print(anomaly)
            logger.warning(anomaly)

    # Generate a report
    generate_report(packet_counter)


def generate_report(packet_counter):
    # Write a summary report to a file
    report_file_path = os.path.join(script_directory, 'anomaly_detection_report.txt')
    with open(report_file_path, 'w') as report_file:
        report_file.write("Anomaly Detection Report\n")
        report_file.write(f"Total Packets: {sum(packet_counter.values())}\n")
        report_file.write(f"High Traffic Volume Threshold: {traffic_threshold}\n\n")

        if port_anomalies:
            report_file.write("Anomalies detected:\n")
            for anomaly in port_anomalies:
                report_file.write(anomaly + '\n')


if __name__ == "__main__":
    start_sniffing()
