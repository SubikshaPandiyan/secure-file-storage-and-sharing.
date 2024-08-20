# Secure-File-Storage-and-Sharing.
This project involves creating a secure file storage and sharing system using Flask, MongoDB, and AES encryption. Users can securely upload, store, and share files, with strict access control via password protection. The platform prioritizes file security and confidentiality, ensuring only authorized users can access and decrypt shared files.

# Technologies Used:
- Backend: Flask (Python)  
- Database: MongoDB  
- Encryption: AES (Advanced Encryption Standard) in CBC mode, PBKDF2 for key derivation  
- Frontend: HTML, CSS, JavaScript  
- Utilities: Flask sessions for user authentication, werkzeug.security for password hashing  
- Deployment: Flask development server  

# Key Features:
+ **User Authentication:**  Secure registration and login with hashed passwords.  
+ **File Upload & Encryption:**  Files are encrypted with AES using a unique user password before storage.  
+ **File Decryption & Download:** Users can decrypt and download files with the correct password.  
+ **Secure Sharing:** Files can be shared with other users, with access controlled by the owner.  
+ **Access Control & Notifications:** Shared file access is managed with notifications for approval or denial.  
+ **File Re-encryption:** Files are re-encrypted with the recipient's password upon access approval.  
+ **Security:**  All operations are secured, and AES encryption with PBKDF2 ensures strong file protection.  

# Challenges Addressed:
+ **Secure File Handling:** Ensures secure storage and sharing with strong encryption.  
+ **User Access Control:** Guarantees only authorized users can access shared files through password protection and re-encryption.  
+ **Notification Management:** Efficiently manages access requests with an intuitive interface for controlling file-sharing permissions.

# Project Outcomes:
+ Implemented a secure file storage system enabling confident file upload, encryption, and sharing.
+ Ensured file accessibility only with the correct decryption password, maintaining data confidentiality and integrity.
+ Developed a notification system for managing file access requests, enhancing user experience and control.
