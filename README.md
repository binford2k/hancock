# Docs to come

* GUI
  * Generate SSL certs and drop them in /certs
    * `openssl genrsa -out server.key 1024`
    * `openssl req -new -key server.key -out server.csr`
    * `openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt`
  * Point a web browser at port 8080
    * default user/pass is admin/admin
  * Clicky clicky
* Command line
  * Run the puppet agent to generate certs & submit CSR
  * `curl -k https://server:8080/autosign/\`puppet agent --fingerprint\``

