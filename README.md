# HNSDoH Status
This is a simple webserver to check the status of the Handshake DoH server.

It will check every 5 minutes to see if each node is up and running. It checks the node for plain dns, DNS over HTTPS, and DNS over TLS. For DNS over HTTPS and DNS over TLS, it will check the certificate to make sure it is valid.
