<img src="https://github.com/SecurePwn/pcapsuite/blob/main/logos/2.png" width="20%" height="20%">

# pcapsuite
This project is to help malware and network analysts to help identify and extract some information before actually analyzing it so they have a good mind map for what they need to look into. 
# Pcap Suite v1.0

> A versatile network forensics tool developed by [SecurePwn](https://linkedin.com/company/secure-pwn).

## Overview

Pcap Suite is a network forensics tool that empowers cybersecurity professionals to delve deep into network traffic, detect specific file signatures, and analyze network activities in the context of file transfer. Whether you're hunting for malicious files or exploring files transfers, Pcap Suite is your go-to solution.

## Features

- **File Magic Byte Detection**: Pcap Suite allows you to specify a file's magic byte and then hunts for it within a PCAP file. This feature is invaluable when searching for specific files in network traffic.

- **Summary of Detected Files**: Get an overview of how many magic files were detected within the PCAP file. Keep in mind that while it provides valuable insights, there might be occasional false positives.

- **Detailed Information**: For each detected file, Pcap Suite provides a treasure trove of details. You can view the packet number, source and destination IPs, involved ports, and much more.

- **User-Friendly GUI Interface**: With a command line, Pcap Suite boasts an intuitive GUI interface based on Flask. Its user-friendly nature makes it accessible to both seasoned professionals and beginners. Moreover, it's open for customization and the addition of new features.

## Installation

- Clone the repository from [GitHub](https://github.com/[SecurePwn]/[Pcap-Suite]).

- Install the required dependencies using PIP.
### Command-Line
- Start the application in the command-line by running ``python3 ./pycap.py``.
  #### Usage:-
  ```Python3 pcap.py <pcap_path> <scan_type> <magic_bytes if required>```

  #### Example:-
  ```
  python3 pycap.py scan.pcap --scanmagic '89 50 4E 47 0D 0A 1A 0A'
  ```
### GUI
 ```
  cd flask
  ```
```
python3 app.py
```

## Usage

1. Launch the Pcap Suite application.

2. Specify the magic byte of the file you want to detect.

3. Load the PCAP file you want to analyze.

4. Initiate the analysis, and Pcap Suite will provide you with valuable insights.

## Contributing

Contributions are welcome. Feel free to fork the project, create your feature branches, and submit a pull request. Alternatively, you can log issues in the [Issues](https://github.com/[SecurePwn]/[Pcap-Suite]/issues) section.

## Contact

SecurePwn - [LinkedIn](https://linkedin.com/company/secure-pwn)
Instagram - [Instagram](https://instagram.com/securepwn)

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Follow%20us-blue)](https://linkedin.com/company/secure-pwn)
Email: syedalizain03@gmail.com

### Personal details
- LinkedIn: [Linkedin.com/in/syedalizain033](https://linkedin.com/in/syedalizain033)
- Instagram: [Instagram.com/syedalizain033](https://instagram.com/syedalizain033)

