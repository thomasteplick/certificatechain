# certificatechain
Create an x509v3 certificate chain for RSA or ECDSA public key algorithms.
This program is a web application for constructing an x509v3 certificate chain.  The public key algorithms supported are RSA and ECDSA.  For RSA, key sizes 2048, 3072,
and 4096 bits are available.  For ECDSA, key sizes 256, 384, and 512 bits are available.  A root CA, zero, one, or two intermediate CAs, and an end-entity certificate
are created.  The backend is written in Go using the html/template package for support.  After starting the server, the user connects to URL 
http://127.0.0.1:8080/certchain in the web browser.  The user fills in the form, being careful to select the number of intermediate CAs.  Clicking the submit button
uploads the form data to the server.  Any errors in the form entries are highlighted in red.  Upon successful submission of the form, the certificate chain is displayed
in the browser using the openssl x509 -text command.



![image](https://user-images.githubusercontent.com/117768679/214162390-371c443a-ff52-4efa-bcce-66d8064cbdc9.png)
![image](https://user-images.githubusercontent.com/117768679/214163832-e35f252e-aa77-4e9b-b5d6-b2f6e646ab25.png)
![image](https://user-images.githubusercontent.com/117768679/214164045-7b9a5d9c-3ada-43dc-b3d6-8c50b0c15d63.png)
![image](https://user-images.githubusercontent.com/117768679/214164265-744d42bc-36f8-48be-896d-39130256bf80.png)
