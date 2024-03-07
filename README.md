# PGP Encryption Decryption in Java using Bouncy Castle Library

# PGP Encryption and Decryption Utility
This Java application provides functionality to encrypt files using PGP (Pretty Good Privacy) encryption and decrypt PGP encrypted files. It utilizes the Bouncy Castle library for PGP functionality.

# Features
1) Encryption: Encrypt files using PGP encryption with a specified public key.
2) Decryption: Decrypt PGP encrypted files using the corresponding private key.
3) Logging: Logs activities to files for monitoring and debugging purposes.
4) Configuration: Utilizes a properties file for configuration of input/output directories, key paths, and other settings.

# Usage
1) Configuration: Edit the config.properties file located in the application directory to set input/output directories, key paths, and other configurations.

2) Encryption: Place files to be encrypted in the input directory specified in the config.properties file. Run the PGPencryption.java file to encrypt the files using the specified public key. Encrypted files will be stored in the output directory specified in the config.properties file. Original files will be moved to the backup directory after encryption.

3) Decryption: Place PGP encrypted files in the input directory specified in the config.properties file. Run the PGPdecryption.java file to decrypt the encrypted files using the specified private key and passphrase. Decrypted files will be stored in the output directory specified in the config.properties file. Encrypted files will be moved to the backup directory after decryption.

4) Dependencies:
Bouncy Castle Library: Provides PGP functionality for encryption and decryption.

# Requirements
a) Java Development Kit (JDK) version 8 or higher.
b) Bouncy Castle library.
c) Setup
d) Clone the repository to your local machine.
e) Ensure JDK and Bouncy Castle library are installed.
f) Edit the config.properties file with appropriate configurations.
g) Compile and run PGPencryption.java and PGPdecryption.java files.

# License
This project is licensed under the MIT License.

# Authors
Shubham Ketkar
shubhamketkar.work@gmail.com

# Acknowledgments
Special thanks to the developers of the Bouncy Castle library for their contributions to cryptographic functions in Java.

# Contribution Guidelines
Please submit any bug reports, feature requests, or contributions via GitHub issues and pull requests.

# Disclaimer
This application is provided as-is without any warranty. Users are responsible for the security and proper usage of their encryption keys and data.

# For any questions or support, please contact - shubhamketkar.work@gmail.com.
