# Secure Chat Application

## Background

This project is a secure chat application designed to provide encrypted communication using advanced cryptographic techniques. It incorporates functionalities such as Diffie-Hellman key exchange for establishing a shared secret, AES-256 for encryption, and HMAC for message integrity and authentication. The application is built with the intent to demonstrate secure communication principles in a networked environment.


## Features

### Ephemeral Key Handshake Protocol with Perfect Forward Secrecy
- **Implementation:** The application uses a handshake protocol based on Diffie-Hellman key exchange to establish ephemeral session keys. These keys are temporary and discarded after the session, ensuring that even if long-term keys are compromised, past communications remain secure—a principle known as Perfect Forward Secrecy (PFS).
- **Security Benefit:** This approach prevents potential eavesdroppers from decrypting intercepted communications even if they obtain private keys after the communication has occurred.

### Mutual Authentication Using Public Key Cryptography
- **Implementation:** Both parties authenticate each other using public key cryptography before establishing a secure channel. This process involves verifying each other's identities through digital signatures and public keys which are pre-exchanged or distributed via a trusted channel.
- **Security Benefit:** Mutual authentication ensures that the entities involved in the communication are indeed who they claim to be, preventing impersonation and man-in-the-middle attacks.

### Encrypted Messages with Message Authentication Codes (MACs)
- **Implementation:** Once a secure channel is established, every message sent over this channel is encrypted and accompanied by a MAC. Encryption is performed using AES-256-CBC, and MACs are generated using HMAC with SHA-256.
- **Security Benefit:** Encryption ensures that the messages are confidential and can only be read by the intended recipient, while MACs ensure the integrity and authenticity of the messages, verifying that they have not been altered in transit.

### Replay Attack Prevention
- **Implementation:** The protocol includes timestamps to ensure that old messages cannot be replayed to achieve unauthorized effects. These measures are integrated into the message payload, contributing to the overall security posture of the communication process.
- **Security Benefit:** Preventing replay attacks is crucial for the security of stateful sessions and ensures that each message is unique and valid for a specific session only, thus safeguarding against various forms of replay-based exploits.



## Installation

### Prerequisites

Before compiling and running the application, ensure you have the following dependencies installed:

- GTK+ 3
- OpenSSL
- GMP

### Installing Dependencies


