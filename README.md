# Simple Network Enumerator

## Introduction

Simple Network Enumerator is a passive network scanner designed to monitor network traffic, detect suspicious activity, and display network packet details in real-time. It captures packets traversing the network and provides insights into network traffic patterns, including source and destination IP addresses, ports, protocols, and timestamps.

## Features

- **Passive Packet Capture**: Capture network packets without actively sending any traffic.
- **Real-time Monitoring**: Display network packet details in real-time.
- **Protocol Support**: Support for both IPv4 and IPv6 protocols.
- **Suspicious Activity Detection**: Detect suspicious activity based on predefined conditions.
- **Web Interface**: Visualize network packet details through a web interface.
- **Sorting and Filtering**: Sort and filter packet details based on various parameters.
- **Export Functionality**: Export captured packet details to CSV format for further analysis.

## Requirements

- Python 3.x
- Scapy
- Flask
- Rich (for terminal UI)
- urwid (for terminal UI)

## Installation

1. Clone the repository:

```bash
git clone https://github.com/DTRHnet/SNEnum.git
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Run the application:

```bash
python3 SNEnum.py
```

## Access the web interface:
Open a web browser and navigate to http://localhost:5000 to view network packet details.

## Monitor network traffic:
The application will start capturing network packets and display them in real-time on the web interface.

## Configuration
You can configure suspicious activity detection conditions in the process_packet function of SNEnum.py
Customize logging settings in logging.basicConfig calls in main.py.
Adjust the refresh rate and other parameters in the update_display function of SNEnum.py

## Contributing
Contributions are welcome! If you want to contribute to Simple Network Enumerator, please fork the repository, make your changes, and submit a pull request.

## License
This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments
Scapy - Powerful packet manipulation tool and library.
Flask - Web framework for Python.
Rich - Rich terminal formatting library.
urwid - Console user interface library.

## Contact
For any inquiries or support, please contact admin@dtrh.net

DTRH.net
