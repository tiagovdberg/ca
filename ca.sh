#!/bin/bash
#
# Certificate Authority Example Script
# Copyright (C) 2018 Tiago van den Berg

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
mkdir -p ~/ca
cd ~/ca
rm -vrf certs crl newcerts private password index.txt openssl.cnf 'export' serial serial.* index.txt index.txt.* req self intermediate_ca_cert.sh *.ca ca.cnf
if [ "x${1}" == "xclean" ] ; then
	exit
fi 

mkdir -p certs crl newcerts private password req export self/certs self/password self/private self/req
chmod 700 private password
touch index.txt
echo 1000 > serial
cat > self/req/ca.req.cnf << EOF
[ req ]
# Options for the 'req' tool ('man req').
default_bits        = 2048
distinguished_name  = req_distinguished_name
#prompt              = no
string_mask         = utf8only

# SHA-1 is deprecated, so use SHA-2 instead.
default_md          = sha256

# Extension to add when the -x509 option is used.
x509_extensions     = v3_ca

##########################################################################
# The [ req_distinguished_name ] section declares the information normally required in a certificate signing request. You can optionally specify some defaults.
##########################################################################

[ req_distinguished_name ]
# See <https://en.wikipedia.org/wiki/Certificate_signing_request>.
countryName                     = Country Name (2 letter code)
stateOrProvinceName             = State or Province Name
localityName                    = Locality Name
0.organizationName              = Organization Name
organizationalUnitName          = Organizational Unit Name
commonName                      = Common Name
emailAddress                    = Email Address

# Optionally, specify some defaults.
countryName_default             = BR
stateOrProvinceName_default     = 'Distrito Federal'
localityName_default            = 'Riot Emergence Street'
0.organizationName_default      = 'Riot Emergence Organization'
organizationalUnitName_default  = 'Certification Authority Department'
commonName_default              = 'Root CA'
emailAddress_default            = 'rootca@riotemergence.org'

##########################################################################
# The next few sections are extensions that can be applied when signing certificates. For example, passing the -extensions v3_ca command-line argument will apply the options set in [ v3_ca ].
# We’ll apply the v3_ca extension when we create the root certificate.
##########################################################################

[ v3_ca ]
# Extensions for a typical CA ('man x509v3_config').
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
EOF

echo '##########################################################################'
echo '# Creating Private CA Key'
echo '##########################################################################'

echo ca.key > self/password/ca.key.password.txt

openssl genrsa -aes256 -passout file:self/password/ca.key.password.txt -out self/private/ca.key.pem 4096
openssl pkey -in self/private/ca.key.pem -out self/private/ca.unencryptedkey.pem -passin file:self/password/ca.key.password.txt
chmod 400 self/private/ca.key.pem

echo '##########################################################################'
echo '# Creating Root CA Certificate'
echo '##########################################################################'

openssl req -config self/req/ca.req.cnf \
      -key self/private/ca.key.pem -passin file:self/password/ca.key.password.txt \
      -new -x509 -days 7300 -sha256 -extensions v3_ca \
      -out self/certs/ca.cert.pem
chmod 444 self/certs/ca.cert.pem
ln -sf ca.cert.pem self/certs/$(openssl x509 -noout -hash -in "self/certs/ca.cert.pem").0
keytool -importcert -keystore export/Truststore.jks -storetype jks -storepass changeit -alias root-ca -file self/certs/ca.cert.pem -noprompt -trustcacerts

cat > ca.cnf << EOF
###############################################################################
# The [ ca ] section is mandatory. Here we tell OpenSSL to use the options from the [ CA_default ] section.
###############################################################################

[ ca ]
# 'man ca'
default_ca = CA_default

###############################################################################
# The [ CA_default ] section contains a range of defaults. Make sure you declare the directory you chose earlier (ca).
###############################################################################

[ CA_default ]
# Directory and file locations.
dir               = `echo ~`/ca
certs             = \$dir/certs
crl_dir           = \$dir/crl
new_certs_dir     = \$dir/newcerts
database          = \$dir/index.txt
serial            = \$dir/serial
RANDFILE          = \$dir/private/.rand

# The root key and root certificate.
private_key       = \$dir/self/private/ca.key.pem
certificate       = \$dir/self/certs/ca.cert.pem


# For certificate revocation lists.
crlnumber         = $dir/crlnumber
crl               = $dir/crl/ca.crl.pem
crl_extensions    = crl_ext
default_crl_days  = 30

# SHA-1 is deprecated, so use SHA-2 instead.
default_md        = sha256

name_opt          = ca_default
cert_opt          = ca_default
default_days      = 375
preserve          = no
policy            = policy_strict

##########################################################################
# We’ll apply policy_strict for all root CA signatures, as the root CA is only being used to create intermediate CAs.
##########################################################################

[ policy_strict ]
# The root CA should only sign intermediate certificates that match.
# See the POLICY FORMAT section of 'man ca'.
countryName             = match
stateOrProvinceName     = match
organizationName        = match
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

##########################################################################
# The next few sections are extensions that can be applied when signing certificates. For example, passing the -extensions v3_intermediate_ca command-line argument will apply the options set in [ v3_intermediate_ca ].
##########################################################################

[ v3_intermediate_ca ]
# Extensions for a typical intermediate CA ('man x509v3_config').
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

##########################################################################
# The crl_ext extension is automatically applied when creating certificate revocation lists.
##########################################################################

[ crl_ext ]
# Extension for CRLs ('man x509v3_config').
authorityKeyIdentifier=keyid:always

##########################################################################
# We’ll apply the ocsp extension when signing the Online Certificate Status Protocol (OCSP) certificate.
##########################################################################

[ ocsp ]
# Extension for OCSP signing certificates ('man ocsp').
basicConstraints = CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, OCSPSigning
EOF

cat > intermediate_ca_cert.sh << EOF
#!/bin/bash
#
# Certificate Authority Example Script
# Copyright (C) 2018 Tiago van den Berg

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
INTERMEDIATE_NAME=\${1}

cat > req/"\$INTERMEDIATE_NAME.req.cnf" << EOFREQ
[ req ]
# Options for the 'req' tool ('man req').
default_bits        = 2048
distinguished_name  = req_distinguished_name
#prompt              = no
string_mask         = utf8only

# SHA-1 is deprecated, so use SHA-2 instead.
default_md          = sha256

[ req_distinguished_name ]
# See <https://en.wikipedia.org/wiki/Certificate_signing_request>.
countryName                     = Country Name (2 letter code)
stateOrProvinceName             = State or Province Name
localityName                    = Locality Name
0.organizationName              = Organization Name
organizationalUnitName          = Organizational Unit Name
commonName                      = Common Name
emailAddress                    = Email Address

# Optionally, specify some defaults.
countryName_default             = BR
stateOrProvinceName_default     = Distrito Federal
localityName_default            = Riot Emergence Street
0.organizationName_default      = Riot Emergence Organization
organizationalUnitName_default  = Certificates Issuing Departament
commonName_default              = \$INTERMEDIATE_NAME
emailAddress_default            = 'certificates@riotemergence.org'

EOFREQ

echo \$INTERMEDIATE_NAME.key > password/"\$INTERMEDIATE_NAME.key.password.txt"

openssl genrsa -aes256 -passout file:password/"\$INTERMEDIATE_NAME.key.password.txt" \
      -out private/"\$INTERMEDIATE_NAME.key.pem" 4096
openssl pkey -in private/"\$INTERMEDIATE_NAME.key.pem" -out private/"\$INTERMEDIATE_NAME.unencryptedkey.pem" -passin file:password/"\$INTERMEDIATE_NAME.key.password.txt"
chmod 400 private/"\$INTERMEDIATE_NAME.key.pem"

openssl req -config req/"\$INTERMEDIATE_NAME.req.cnf" -new -sha256 \
      -key private/"\$INTERMEDIATE_NAME.key.pem" -passin file:password/"\$INTERMEDIATE_NAME.key.password.txt" \
      -out req/"\$INTERMEDIATE_NAME.req.pem"

openssl ca -config ca.cnf -batch -extensions v3_intermediate_ca \
      -days 3650 -notext -md sha256 -passin file:self/password/ca.key.password.txt \
      -in req/"\$INTERMEDIATE_NAME.req.pem" \
      -out certs/"\$INTERMEDIATE_NAME.cert.pem"
cat certs/"\$INTERMEDIATE_NAME.cert.pem" self/certs/ca.cert.pem > certs/"\$INTERMEDIATE_NAME.certchain.pem"

ln -sfv "\$INTERMEDIATE_NAME.cert.pem" certs/\$(openssl x509 -noout -hash -in certs/"\$INTERMEDIATE_NAME.cert.pem").0

mkdir -p "\$INTERMEDIATE_NAME.ca" "\$INTERMEDIATE_NAME.ca"/certs "\$INTERMEDIATE_NAME.ca"/crl "\$INTERMEDIATE_NAME.ca"/newcerts "\$INTERMEDIATE_NAME.ca"/private "\$INTERMEDIATE_NAME.ca"/password "\$INTERMEDIATE_NAME.ca"/req "\$INTERMEDIATE_NAME.ca"/self "\$INTERMEDIATE_NAME.ca"/self/certs "\$INTERMEDIATE_NAME.ca"/self/password "\$INTERMEDIATE_NAME.ca"/self/private "\$INTERMEDIATE_NAME.ca"/self/req "\$INTERMEDIATE_NAME.ca"/export
cp -av req/"\$INTERMEDIATE_NAME.req.cnf" "\$INTERMEDIATE_NAME.ca"/self/req
cp -av req/"\$INTERMEDIATE_NAME.req.pem" "\$INTERMEDIATE_NAME.ca"/self/req
cp -av certs/"\$INTERMEDIATE_NAME.cert.pem" "\$INTERMEDIATE_NAME.ca"/self/certs
cp -av certs/"\$INTERMEDIATE_NAME.certchain.pem" "\$INTERMEDIATE_NAME.ca"/self/certs
cp -av certs/\$(openssl x509 -noout -hash -in certs/"\$INTERMEDIATE_NAME.cert.pem").0 "\$INTERMEDIATE_NAME.ca"/self/certs
cp -av private/"\$INTERMEDIATE_NAME.key.pem" "\$INTERMEDIATE_NAME.ca"/self/private
cp -av private/"\$INTERMEDIATE_NAME.unencryptedkey.pem" "\$INTERMEDIATE_NAME.ca"/self/private
cp -av password/"\$INTERMEDIATE_NAME.key.password.txt" "\$INTERMEDIATE_NAME.ca"/self/password


chmod 700 "\$INTERMEDIATE_NAME.ca"/private "\$INTERMEDIATE_NAME.ca"/password
touch "\$INTERMEDIATE_NAME.ca"/index.txt
echo 1000 > "\$INTERMEDIATE_NAME.ca"/serial
echo 1000 > "\$INTERMEDIATE_NAME.ca"/crlnumber
cat > "\$INTERMEDIATE_NAME.ca"/ca.cnf << EOFCACNF
# OpenSSL intermediate CA configuration file.
# Copy to '/root/ca/intermediate/openssl.cnf'.

[ ca ]
# 'man ca'
default_ca = CA_default

[ CA_default ]
# Directory and file locations.
dir               = \`echo ~\`/ca/\`echo \$INTERMEDIATE_NAME.ca\`
certs             = \\\$dir/certs
crl_dir           = \\\$dir/crl
new_certs_dir     = \\\$dir/newcerts
database          = \\\$dir/index.txt
serial            = \\\$dir/serial
RANDFILE          = \\\$dir/private/.rand

# The root key and root certificate.
private_key       = \\\$dir/self/private/\$INTERMEDIATE_NAME.key.pem
certificate       = \\\$dir/self/certs/\$INTERMEDIATE_NAME.cert.pem

# For certificate revocation lists.
crlnumber         = \\\$dir/crlnumber
crl               = \\\$dir/crl/\$INTERMEDIATE_NAME.crl.pem
crl_extensions    = crl_ext
default_crl_days  = 30

# SHA-1 is deprecated, so use SHA-2 instead.
default_md        = sha256

name_opt          = ca_default
cert_opt          = ca_default
default_days      = 375
preserve          = no
policy            = policy_loose

[ policy_strict ]
# The root CA should only sign intermediate certificates that match.
# See the POLICY FORMAT section of 'man ca'.
countryName             = match
stateOrProvinceName     = match
organizationName        = match
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ policy_loose ]
# Allow the intermediate CA to sign a more diverse range of certificates.
# See the POLICY FORMAT section of the 'ca' man page.
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ usr_cert ]
# Extensions for client certificates ('man x509v3_config').
basicConstraints = CA:FALSE
nsCertType = client, email
nsComment = Riot Emergence Client Certificate
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth, emailProtection

[ server_cert ]
# Extensions for server certificates ('man x509v3_config').
basicConstraints = CA:FALSE
nsCertType = server
nsComment = Riot emergence Server Certificate
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = \\\$HOSTCERT

[ crl_ext ]
# Extension for CRLs ('man x509v3_config').
authorityKeyIdentifier=keyid:always

[ ocsp ]
# Extension for OCSP signing certificates ('man ocsp').
basicConstraints = CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, OCSPSigning
EOFCACNF

cat > "\$INTERMEDIATE_NAME.ca"/server_cert.sh << EOFSERVERCERT
#!/bin/bash
#
# Certificate Authority Example Script
# Copyright (C) 2018 Tiago van den Berg

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
HOSTCERT=\\\${1}

if [ x"\\\${HOSTCERT}" == 'x' ] ; then
	echo -n -e "Usage:\n  \${0} {hostname}\n\n"
	exit 1
fi

cat > req/"\\\${HOSTCERT}.req.cnf" << EOFREQ
[ req ]
# Options for the 'req' tool ('man req').
default_bits        = 2048
distinguished_name  = req_distinguished_name
#prompt              = no
string_mask         = utf8only

# SHA-1 is deprecated, so use SHA-2 instead.
default_md          = sha256

##########################################################################
# The [ req_distinguished_name ] section declares the information normally required in a certificate signing request. You can optionally specify some defaults.
##########################################################################

[ req_distinguished_name ]
# See <https://en.wikipedia.org/wiki/Certificate_signing_request>.
countryName                     = Country Name (2 letter code)
stateOrProvinceName             = State or Province Name
localityName                    = Locality Name
0.organizationName              = Organization Name
organizationalUnitName          = Organizational Unit Name
commonName                      = Common Name
emailAddress                    = Email Address

# Optionally, specify some defaults.
countryName_default             = BR
stateOrProvinceName_default     = 'Distrito Federal'
localityName_default            = 'Riot Emergence Street'
0.organizationName_default      = 'Riot Emergence Organization'
organizationalUnitName_default  = 'Certification Authority Department'
commonName_default              = \\\$HOSTCERT
emailAddress_default            = webmaster@\\\$HOSTCERT
EOFREQ

echo "\\\$HOSTCERT.key" > password/"\\\$HOSTCERT.key.password.txt"
openssl genrsa -aes256 -passout file:password/"\\\$HOSTCERT.key.password.txt" \
      -out private/"\\\$HOSTCERT.key.pem" 2048
openssl pkey -in private/"\\\$HOSTCERT.key.pem" -out private/"\\\$HOSTCERT.unencryptedkey.pem" -passin file:password/"\\\$HOSTCERT.key.password.txt"
chmod 400 private/"\\\$HOSTCERT.key.pem"
chmod 400 private/"\\\$HOSTCERT.unencryptedkey.pem"
openssl req -config req/"\\\$HOSTCERT.req.cnf" \
      -key private/"\\\$HOSTCERT.key.pem" -passin file:password/"\\\$HOSTCERT.key.password.txt" \
      -new -sha256 -out req/"\\\$HOSTCERT.req.pem"
openssl ca -config <(cat ca.cnf | sed s/\\\\\\\$HOSTCERT/DNS:\\\$HOSTCERT,URI:https:\\\\\\\\/\\\\\\\\/\\\$HOSTCERT/g) -batch \
      -extensions server_cert -days 375 -notext -md sha256 -passin file:self/password/"\$INTERMEDIATE_NAME.key.password.txt" \
      -in req/"\\\$HOSTCERT.req.pem" \
      -out certs/"\\\$HOSTCERT.cert.pem"
chmod 444 certs/"\\\$HOSTCERT.cert.pem"
cat certs/"\\\$HOSTCERT.cert.pem" \
      self/certs/"\$INTERMEDIATE_NAME.certchain.pem" > certs/"\\\$HOSTCERT.certchain.pem"

echo "\\\$HOSTCERT.pkcs12" > export/"\\\$HOSTCERT.pkcs12.password.txt"
openssl pkcs12 -export -inkey private/"\\\$HOSTCERT.key.pem" -passin file:password/"\\\$HOSTCERT.key.password.txt" -in certs/"\\\$HOSTCERT.cert.pem" -out export/"\\\$HOSTCERT.pkcs12" -name "\\\$HOSTCERT" -noiter -nomaciter -passout file:export/"\\\$HOSTCERT.pkcs12.password.txt"

keytool -importkeystore -srckeystore export/"\\\$HOSTCERT.pkcs12" -srcstoretype pkcs12 -srcstorepass "\\\$HOSTCERT.pkcs12" -srcalias "\\\$HOSTCERT" -srckeypass "\\\$HOSTCERT.pkcs12" -destkeystore export/Keystore.jks -deststoretype jks -deststorepass changeit -destalias "\\\$HOSTCERT" -destkeypass changeit -noprompt
EOFSERVERCERT
chmod +x "\$INTERMEDIATE_NAME.ca"/server_cert.sh
cat > "\$INTERMEDIATE_NAME.ca"/usr_cert.sh << EOFUSRCERT
#!/bin/bash
#
# Certificate Authority Example Script
# Copyright (C) 2018 Tiago van den Berg

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
USRCERT=\\\${1}

if [ x"\\\${USRCERT}" == 'x' ] ; then
	echo -n -e "Usage:\n  \${0} {hostname}\n\n"
	exit 1
fi

cat > req/"\\\${USRCERT}.req.cnf" << EOFREQ
[ req ]
# Options for the 'req' tool ('man req').
default_bits        = 2048
distinguished_name  = req_distinguished_name
#prompt              = no
string_mask         = utf8only

# SHA-1 is deprecated, so use SHA-2 instead.
default_md          = sha256

##########################################################################
# The [ req_distinguished_name ] section declares the information normally required in a certificate signing request. You can optionally specify some defaults.
##########################################################################

[ req_distinguished_name ]
# See <https://en.wikipedia.org/wiki/Certificate_signing_request>.
countryName                     = Country Name (2 letter code)
stateOrProvinceName             = State or Province Name
localityName                    = Locality Name
0.organizationName              = Organization Name
organizationalUnitName          = Organizational Unit Name
commonName                      = Common Name
emailAddress                    = Email Address

# Optionally, specify some defaults.
countryName_default             = BR
stateOrProvinceName_default     = 'Distrito Federal'
localityName_default            = 'Riot Emergence Street'
0.organizationName_default      = 'Riot Emergence Organization'
organizationalUnitName_default  = 'Certification Authority Department'
commonName_default              = \\\$USRCERT
emailAddress_default            = \\\$USRCERT@mail.org
EOFREQ

echo "\\\$USRCERT.key" > password/"\\\$USRCERT.key.password.txt"
openssl genrsa -aes256 -passout file:password/"\\\$USRCERT.key.password.txt" \
      -out private/"\\\$USRCERT.key.pem" 2048
openssl pkey -in private/"\\\$USRCERT.key.pem" -out private/"\\\$USRCERT.unencryptedkey.pem" -passin file:password/"\\\$USRCERT.key.password.txt"
chmod 400 private/"\\\$USRCERT.key.pem"
chmod 400 private/"\\\$USRCERT.unencryptedkey.pem"
openssl req -config req/"\\\$USRCERT.req.cnf" \
      -key private/"\\\$USRCERT.key.pem" -passin file:password/"\\\$USRCERT.key.password.txt" \
      -new -sha256 -out req/"\\\$USRCERT.req.pem"
openssl ca -config ca.cnf -batch \
      -extensions usr_cert -days 375 -notext -md sha256 -passin file:self/password/"\$INTERMEDIATE_NAME.key.password.txt" \
      -in req/"\\\$USRCERT.req.pem" \
      -out certs/"\\\$USRCERT.cert.pem"
chmod 444 certs/"\\\$USRCERT.cert.pem"
cat certs/"\\\$USRCERT.cert.pem" \
      self/certs/"\$INTERMEDIATE_NAME.certchain.pem" > certs/"\\\$USRCERT.certchain.pem"

echo "\\\$USRCERT".pkcs12 > export/"\\\$USRCERT.pkcs12.password.txt"
openssl pkcs12 -export -inkey private/"\\\$USRCERT.key.pem" -passin file:password/"\\\$USRCERT.key.password.txt" -in certs/"\\\$USRCERT.cert.pem" -out export/"\\\$USRCERT.pkcs12" -name "\\\$USRCERT" -noiter -nomaciter -passout file:export/"\\\$USRCERT.pkcs12.password.txt"

keytool -importkeystore -srckeystore export/"\\\$USRCERT.pkcs12" -srcstoretype pkcs12 -srcstorepass "\\\$USRCERT.pkcs12" -srcalias "\\\$USRCERT" -srckeypass "\\\$USRCERT.pkcs12" -destkeystore export/Keystore.jks -deststoretype jks -deststorepass changeit -destalias "\\\$USRCERT" -destkeypass changeit -noprompt
EOFUSRCERT
chmod +x "\$INTERMEDIATE_NAME.ca"/usr_cert.sh
EOF
chmod 755 intermediate_ca_cert.sh

