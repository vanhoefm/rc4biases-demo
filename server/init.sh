#!/bin/bash

# This must be done because the paths in both config files use /usr/share/(nginx|apache2)/rc4https/ as prefix
sudo ln -s "$PWD" /usr/share/nginx/rc4https
sudo ln -s "$PWD" /usr/share/apache2/rc4https

# Enable our website config
sudo ln -s /usr/share/nginx/rc4https/rc4https-nginx /etc/nginx/sites-enabled/rc4https
sudo ln -s /usr/share/apache2/rc4https/rc4https-apache /etc/apache2/sites-enabled/rc4https
