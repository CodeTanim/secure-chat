# Secure Chat Application

## Group Members

- Tanim Islam
- Mansij Mishra

## Background

This project is a secure chat application designed to provide encrypted communication using advanced cryptographic techniques. It incorporates functionalities such as Diffie-Hellman key exchange for establishing a shared secret, AES-256 for encryption, and HMAC for message integrity and authentication. The application is built with the intent to demonstrate secure communication principles in a networked environment.


## Installation

### Prerequisites

Before compiling and running the application, ensure you have the following dependencies installed:

- GTK+ 3
- OpenSSL
- GMP

### Installing Dependencies
On Ubuntu/debian:
```bash
sudo apt-get install libgtk-3-dev libssl-dev libgmp-dev
```

On Mac:
```bash
brew install gtk+3 openssl gmp

```


## How to run

To compile, run:
```bash
make
```

run 
```bash 
./chat -h 
```
and see a list of options. You should be able to test it out like this:

```bash
./chat -l & sleep 1 && ./chat -c localhost &
```

Two windows should pop up, connected over the loopback interface.


## Features

### Ephemeral Key Handshake Protocol with Perfect Forward Secrecy
- **Implementation:** The application uses a handshake protocol based on Diffie-Hellman key exchange to establish ephemeral session keys. These keys are temporary and discarded after the session, ensuring that even if long-term keys are compromised, past communications remain secure—a principle known as Perfect Forward Secrecy (PFS).
- **Security Benefit:** This approach prevents potential eavesdroppers from decrypting intercepted communications even if they obtain private keys after the communication has occurred.

### Mutual Authentication Using Public Key Cryptography
- **Implementation:** Both parties authenticate each other using public key cryptography before establishing a secure channel. This process involves verifying each other's identities through a shared secret computed using 3DH.
- **Security Benefit:** Mutual authentication ensures that the entities involved in the communication are indeed who they claim to be, preventing impersonation and man-in-the-middle attacks.

### Encrypted Messages with Message Authentication Codes (MACs)
- **Implementation:** Once a secure channel is established, every message sent over this channel is encrypted and accompanied by a MAC. Encryption is performed using AES-256-CBC, and MACs are generated using HMAC with SHA-256.
- **Security Benefit:** Encryption ensures that the messages are confidential and can only be read by the intended recipient, while MACs ensure the integrity and authenticity of the messages, verifying that they have not been altered in transit.

### Replay Attack Prevention
- **Implementation:** The protocol includes timestamps to ensure that old messages cannot be replayed to achieve unauthorized effects. These measures are integrated into the message payload, contributing to the overall security posture of the communication process.
- **Security Benefit:** Preventing replay attacks is crucial for the security of stateful sessions and ensures that each message is unique and valid for a specific session only, thus safeguarding against various forms of replay-based exploits.


## Functions Added

### `loadLongTermKey`
- **Purpose:** This function loads or generates long-term Diffie-Hellman keys used for establishing persistent cryptographic contexts. If the specified key file does not exist, the function generates a new key, saves it, and loads it into the provided `dhKey` structure.
- **Usage:** Used during the initialization phase of both the client and the server to ensure each has a long-term key for secure communications.

### `encryptAndSendTestMessage`
- **Purpose:** Encrypts a predefined test message using AES-256-CBC encryption and sends it to the communication partner. This function helps verify that both parties have correctly established a shared cryptographic context using the shared secret.
- **Usage:** Called after establishing a connection, typically used to confirm that encryption and decryption capabilities are functional between endpoints.

### `receiveAndVerifyTestResponse`
- **Purpose:** Receives an encrypted test message and decrypts it using AES-256-CBC. It verifies that the decrypted message matches the expected "authentication-test" message, confirming mutual decryption capability and authenticity.
- **Usage:** Used to confirm the receiving and decrypting capabilities of the communication partner, ensuring mutual authentication and encryption capabilities.

### `computeAndSendHMAC`
- **Purpose:** Computes a SHA-256 HMAC for the given message, encrypts both the message and its HMAC using AES-256-CBC, and sends the result over a network socket. This ensures the integrity and confidentiality of the message. To enhance security against replay attacks, a timestamp is included in the message before computing the HMAC, ensuring that each message is unique and time-bound.
- **Usage:** This function is called whenever a secure message needs to be sent, handling the encryption and integrity verification of outbound messages. It is specifically used to send time-sensitive and tamper-evident communications, thereby preventing the reuse of messages.

### `receiveAndVerifyHMAC`
- **Purpose:** Decrypts an incoming encrypted message and verifies its HMAC to ensure the message's integrity and authenticity. This process is critical for confirming that the message has not been tampered with during transit. The function also checks the timestamp within the decrypted message to ensure it falls within an acceptable time window, thus mitigating replay attacks.
- **Usage:** Invoked to handle the reception of encrypted messages, this function forms the core of secure message reception, verifying integrity and decrypting messages in a secure manner. It plays a crucial role in ensuring that messages are both current and authentic, providing robust defense against replay schemes.


## Other Changes (Configuration for macOS)

### Endian.h Replacement
- macOS does not include the `endian.h` header file as required by our application. To resolve this, a custom `endian.h` was created using a solution from [this Gist](https://gist.github.com/cute/a4e8de36b6d544d9121c7228bb9b94ec) and added to our project directory. This file should provide the necessary functions for endian conversion. Please verify if this implementation aligns well with our application's requirements.

### Compilation Issues and Fixes
During compilation, several issues were addressed related to library linking and implicit function declarations:

1. **GMP Library Functions**:
   - Encountered errors with implicit declarations of `gmp_fprintf` and `gmp_fscanf` which are not recognized under the standard C99.
   - Solution: Explicitly declared these functions in the respective source files to resolve the issue:
     ```c
     extern int gmp_fprintf(FILE *, const char *, ...);
     extern int gmp_fscanf (FILE *, const char *, ...);
     ```

2. **Portability of fscanf**:
   - The use of `%ms` specifier in `fscanf` was not compatible with our macOS system, leading to read failures.
   - Solution: Replaced `%ms` with a buffer and specific string format to safely read input without exceeding buffer limits:
     ```c
     char buffer[1024]; // Buffer size adequate for expected input
     if (fscanf(f, "name:%1023s\n", buffer) != 1) {
         printf("Failed to read name.\n");
         rv = -2; // Use appropriate error handling
         goto end;
     }
     ```
These modifications ensure that the application compiles and runs as expected on macOS, addressing system-specific limitations and improving cross-platform compatibility.


