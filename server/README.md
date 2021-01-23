# Setting up test server

## Directory overview

- `www`: this contains the website we are attacking. You have to host this website on `a.site.com` to run the example cookie bruteforce script.
- `ssl`: config files and the TLS keys that we used in the demo.
- `nyt`: the simulated New York Times website were we injected our attack code it. At the time it was not hosted on HTTPS.
- `r0b.pw`: the JavaScript code that was used to trigger a large number of requests.

## Making a capture

Get one of the captures we made. The code to make the network captures yourself is not public currently.

## Setting up the server

Host the files in the `www` directory of this repository in a nginx or Apache server. This is sufficient to run the bruteforce part of the demonstration.

## Configuring Domains

In the the Linux machine running the attacks add the following to the `/etc/hosts` file:

        <IP>    www.nytimes.com
        <IP>    site.com
        <IP>    a.site.com
        <IP>    r0b.pw

And replace `<IP>` with the IP address that is hosting the website. To run the demo where the cookie is bruteforced, you only have to set up the website `a.site.com` using the PHP files in the directory `www`.

# Debugging

## General Troubleshooting

- Remember to set the `keepalive_requests` and `keepalive_timeout` directive so a single connection is used to handle multiple HTTP requests.
- If you want to automatically dump the headers, make `~/biases/attacks/rc4https/www/headers` writable by `www-data`.
- `502 Bad Gateway`: Install php5-fpm.
- Website doesn't load: Chrome and Firefox no longer allow RC4.
- The bruter will try to resolve `a.site.com` as well. Add an entry to `/etc/hosts` to localhost.
- When using chrome to check whether RC4 is being used, it incorrectly displayed AES is used, while dissecting the handshake with wireshark shows that RC4 is being used. This happens when visiting the top level domain, but now when including a page to load. Occurred using chrome 42.0.2311.135m.

## SSL Configuration

See [https://www.digitalocean.com/community/tutorials/how-to-create-a-ssl-certificate-on-nginx-for-ubuntu-12-04] on how to create SSL keys, and configure nginx to use them.

To create a certificate valid for both `site.com` and `*.site.com` see [http://apetec.com/support/GenerateSAN-CSR.htm].

### Nginx

You need a recent version of nginx. We tested it with `nginx/1.6.2` and `nginx/1.8.0`. Install the latest version on Debian 7 by using debian backports (this contains all needed modules and is recent enough). Load the SSL/TLS key as in the example configuration.

### Apache2

1. First enable ssl module using `sudo a2enmod ssl`
2. Restart apache2 with `sudo service apache2 restart`

### Installing certificates on the victim

Installing Certificate on Windows: Open the `server.crt` file on windows, and click on "Install Certificate" in the window. Be sure to install in the "Trusted Root Certification Authorities" store (you have to manually select this).

