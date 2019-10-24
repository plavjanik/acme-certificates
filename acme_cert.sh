#!/bin/bash

OUTPUT_DIR="out"
V="-v"

ROOT_CA_ALIAS="Acme Root CA"
ROOT_CA_FILENAME="${OUTPUT_DIR}/rootca"
ROOT_CA_DNAME="CN=Acme Root CA, OU=Mainframe Department, O=Acme, L=Fairfield, S=New Jersey, C=US"
ROOT_CA_PASSWORD="rootcapassword"
ROOT_CA_VALIDITY=3650

INTER_CA_ALIAS="Acme Internal CA"
INTER_CA_FILENAME="${OUTPUT_DIR}/interca"
INTER_CA_DNAME="CN=Acme Internal CA, OU=Mainframe Department, O=Acme, L=Fairfield, S=New Jersey, C=US"
INTER_CA_PASSWORD="intercapassword"
INTER_CA_VALIDITY=365

SIGNING_CA_ALIAS="Acme Signing CA"
SIGNING_CA_FILENAME="${OUTPUT_DIR}/signingca"
SIGNING_CA_DNAME="CN=Acme Signing CA, OU=Mainframe Department, O=Acme, L=Fairfield, S=New Jersey, C=US"
SIGNING_CA_PASSWORD="signingcapassword"
SIGNING_CA_VALIDITY=365

SERVICE_ALIAS="Server"
SERVICE_PASSWORD="password"
SERVICE_FILENAME="${OUTPUT_DIR}/server"
SERVICE_KEYSTORE="${SERVICE_FILENAME}"
SERVICE_DNAME="CN=Server, OU=Mainframe Department, O=Acme, L=Fairfield, S=New Jersey, C=US"
SERVICE_EXT="SAN=dns:acme.example.com,dns:localhost.localdomain,dns:localhost"
SERVICE_VALIDITY=365
SERVICE_STORETYPE="PKCS12"

if [ -z ${TEMP_DIR+x} ]; then
    TEMP_DIR=/tmp
fi

function pkeytool {
    ARGS=$@
    echo "Calling keytool $ARGS"
    if [ "$LOG" != "" ]; then
        keytool "$@" >> $LOG 2>&1
    else
        keytool "$@"
    fi
    RC=$?
    echo "keytool returned: $RC"
    if [ "$RC" -ne "0" ]; then
        exit 1
    fi
}

### Cleanup

rm -rf ${OUTPUT_DIR}
mkdir -p ${OUTPUT_DIR}

### Root CA

echo "Generate keystore with the root CA private key and root CA public certificate:"
pkeytool -genkeypair -alias "${ROOT_CA_ALIAS}" -keyalg RSA -keysize 2048 -keystore ${ROOT_CA_FILENAME}.keystore.p12 \
    -dname "${ROOT_CA_DNAME}" -keypass "${ROOT_CA_PASSWORD}" -storepass "${ROOT_CA_PASSWORD}" -storetype PKCS12 \
    -validity ${ROOT_CA_VALIDITY} -ext KeyUsage="keyCertSign" -ext BasicConstraints:"critical=ca:true"

echo "Export root CA public certificate:"
pkeytool -export $V -alias "${ROOT_CA_ALIAS}" -file ${ROOT_CA_FILENAME}.cer -keystore ${ROOT_CA_FILENAME}.keystore.p12 -rfc \
    -keypass ${ROOT_CA_PASSWORD} -storepass ${ROOT_CA_PASSWORD} -storetype PKCS12

### Internal

echo "Generate keystore with the internal CA private key and internal CA public certificate:"
pkeytool -genkeypair -alias "${INTER_CA_ALIAS}" -keyalg RSA -keysize 2048 -keystore ${INTER_CA_FILENAME}.keystore.p12 \
    -dname "${INTER_CA_DNAME}" -keypass "${INTER_CA_PASSWORD}" -storepass "${INTER_CA_PASSWORD}" -storetype PKCS12 \
    -validity ${INTER_CA_VALIDITY} -ext KeyUsage="keyCertSign" -ext BasicConstraints:"critical=ca:true"

echo "Generate CSR for the internal CA certificate:"
pkeytool -certreq $V -alias "${INTER_CA_ALIAS}" -keystore ${INTER_CA_FILENAME}.keystore.p12 -storepass ${INTER_CA_PASSWORD} -file ${INTER_CA_FILENAME}.csr \
    -keyalg RSA -storetype PKCS12 -dname "${INTER_CA_DNAME}" -validity ${INTER_CA_VALIDITY}

echo "Sign the CSR using the Root Certificate Authority:"
pkeytool -gencert $V -infile ${INTER_CA_FILENAME}.csr -outfile ${INTER_CA_FILENAME}_signed.cer -keystore ${ROOT_CA_FILENAME}.keystore.p12 \
    -alias "${ROOT_CA_ALIAS}" -keypass ${ROOT_CA_PASSWORD} -storepass ${ROOT_CA_PASSWORD} -storetype PKCS12 \
    -ext BasicConstraints:"critical=ca:true"  -ext KeyUsage="keyCertSign" -validity ${INTER_CA_VALIDITY} -rfc

echo "Import the Root Certificate Authority to the keystore:"
pkeytool -importcert $V -trustcacerts -noprompt -file ${ROOT_CA_FILENAME}.cer -alias "${ROOT_CA_ALIAS}" -keystore ${INTER_CA_FILENAME}.keystore.p12 -storepass ${INTER_CA_PASSWORD} -storetype PKCS12

echo "Import the signed CSR to the keystore:"
pkeytool -importcert $V -trustcacerts -noprompt -file ${INTER_CA_FILENAME}_signed.cer -alias "${INTER_CA_ALIAS}" -keystore ${INTER_CA_FILENAME}.keystore.p12 -storepass ${INTER_CA_PASSWORD} -storetype PKCS12

echo "Export internal CA public certificate:"
pkeytool -export $V -alias "${INTER_CA_ALIAS}" -file ${INTER_CA_FILENAME}.cer -keystore ${INTER_CA_FILENAME}.keystore.p12 -rfc \
    -keypass ${INTER_CA_PASSWORD} -storepass ${INTER_CA_PASSWORD} -storetype PKCS12

### Signing CA

echo "Generate keystore with the signing CA private key and signing CA public certificate:"
pkeytool -genkeypair -alias "${SIGNING_CA_ALIAS}" -keyalg RSA -keysize 2048 -keystore ${SIGNING_CA_FILENAME}.keystore.p12 \
    -dname "${SIGNING_CA_DNAME}" -keypass "${SIGNING_CA_PASSWORD}" -storepass "${SIGNING_CA_PASSWORD}" -storetype PKCS12 \
    -validity ${SIGNING_CA_VALIDITY} -ext KeyUsage="keyCertSign" -ext BasicConstraints:"critical=ca:true"

echo "Generate CSR for the signing CA certificate:"
pkeytool -certreq $V -alias "${SIGNING_CA_ALIAS}" -keystore ${SIGNING_CA_FILENAME}.keystore.p12 -storepass ${SIGNING_CA_PASSWORD} -file ${SIGNING_CA_FILENAME}.csr \
    -keyalg RSA -storetype PKCS12 -dname "${SIGNING_CA_DNAME}" -validity ${SIGNING_CA_VALIDITY}

echo "Sign the CSR using the Internal Certificate Authority:"
pkeytool -gencert $V -infile ${SIGNING_CA_FILENAME}.csr -outfile ${SIGNING_CA_FILENAME}_signed.cer -keystore ${INTER_CA_FILENAME}.keystore.p12 \
    -alias "${INTER_CA_ALIAS}" -keypass ${INTER_CA_PASSWORD} -storepass ${INTER_CA_PASSWORD} -storetype PKCS12 \
    -ext BasicConstraints:"critical=ca:true"  -ext KeyUsage="keyCertSign" -validity ${SIGNING_CA_VALIDITY} -rfc

echo "Import the Root Certificate Authority to the keystore:"
pkeytool -importcert $V -trustcacerts -noprompt -file ${ROOT_CA_FILENAME}.cer -alias "${ROOT_CA_ALIAS}" -keystore ${SIGNING_CA_FILENAME}.keystore.p12 -storepass ${SIGNING_CA_PASSWORD} -storetype PKCS12

echo "Import the Internal Certificate Authority to the keystore:"
pkeytool -importcert $V -trustcacerts -noprompt -file ${INTER_CA_FILENAME}.cer -alias "${INTER_CA_ALIAS}" -keystore ${SIGNING_CA_FILENAME}.keystore.p12 -storepass ${SIGNING_CA_PASSWORD} -storetype PKCS12

echo "Import the signed CSR to the keystore:"
pkeytool -importcert $V -trustcacerts -noprompt -file ${SIGNING_CA_FILENAME}_signed.cer -alias "${SIGNING_CA_ALIAS}" -keystore ${SIGNING_CA_FILENAME}.keystore.p12 -storepass ${SIGNING_CA_PASSWORD} -storetype PKCS12

echo "Export signing CA public certificate:"
pkeytool -export $V -alias "${SIGNING_CA_ALIAS}" -file ${SIGNING_CA_FILENAME}.cer -keystore ${SIGNING_CA_FILENAME}.keystore.p12 -rfc \
    -keypass ${SIGNING_CA_PASSWORD} -storepass ${SIGNING_CA_PASSWORD} -storetype PKCS12

### Service

echo "Generate service private key and service certificate:"
pkeytool -genkeypair $V -alias ${SERVICE_ALIAS} -keyalg RSA -keysize 2048 -keystore ${SERVICE_KEYSTORE}.p12 -keypass ${SERVICE_PASSWORD} -storepass ${SERVICE_PASSWORD} \
    -storetype PKCS12 -dname "${SERVICE_DNAME}" -validity ${SERVICE_VALIDITY}

cp -v ${SERVICE_KEYSTORE}.p12 ${SERVICE_KEYSTORE}_unsigned.p12

echo "Generate CSR for the the service certificate:"
pkeytool -certreq $V -alias "${SERVICE_ALIAS}" -keystore ${SERVICE_KEYSTORE}.p12 -storepass ${SERVICE_PASSWORD} -file ${SERVICE_FILENAME}.csr \
    -keyalg RSA -storetype PKCS12 -dname "${SERVICE_DNAME}" -validity ${SERVICE_VALIDITY}

# echo "Sign the CSR using the Internal Certificate Authority:"
# pkeytool -gencert $V -infile ${SERVICE_FILENAME}.csr -outfile ${SERVICE_FILENAME}_signed.cer -keystore ${INTER_CA_FILENAME}.keystore.p12 \
#     -alias ${INTER_CA_ALIAS} -keypass ${INTER_CA_PASSWORD} -storepass ${INTER_CA_PASSWORD} -storetype PKCS12 \
#     -ext ${SERVICE_EXT} -ext KeyUsage:critical=keyEncipherment,digitalSignature,nonRepudiation,dataEncipherment -ext ExtendedKeyUsage=clientAuth,serverAuth -rfc \
#     -validity ${SERVICE_VALIDITY}

echo "Sign the CSR using the Signing Certificate Authority:"
pkeytool -gencert $V -infile ${SERVICE_FILENAME}.csr -outfile ${SERVICE_FILENAME}_signed.cer -keystore ${SIGNING_CA_FILENAME}.keystore.p12 \
    -alias "${SIGNING_CA_ALIAS}" -keypass ${SIGNING_CA_PASSWORD} -storepass ${SIGNING_CA_PASSWORD} -storetype PKCS12 \
    -ext ${SERVICE_EXT} -ext KeyUsage:critical=keyEncipherment,digitalSignature,nonRepudiation,dataEncipherment -ext ExtendedKeyUsage=clientAuth,serverAuth -rfc \
    -validity ${SERVICE_VALIDITY}

echo "Import the Root Certificate Authority to the keystore:"
pkeytool -importcert $V -trustcacerts -noprompt -file ${ROOT_CA_FILENAME}.cer -alias "${ROOT_CA_ALIAS}" -keystore ${SERVICE_KEYSTORE}.p12 -storepass ${SERVICE_PASSWORD} -storetype PKCS12

echo "Import the Internal Certificate Authority to the keystore:"
pkeytool -importcert $V -trustcacerts -noprompt -file ${INTER_CA_FILENAME}.cer -alias "${INTER_CA_ALIAS}" -keystore ${SERVICE_KEYSTORE}.p12 -storepass ${SERVICE_PASSWORD} -storetype PKCS12

echo "Import the Signing Certificate Authority to the keystore:"
pkeytool -importcert $V -trustcacerts -noprompt -file ${SIGNING_CA_FILENAME}.cer -alias "${SIGNING_CA_ALIAS}" -keystore ${SERVICE_KEYSTORE}.p12 -storepass ${SERVICE_PASSWORD} -storetype PKCS12

echo "Import the signed CSR to the keystore:"
pkeytool -importcert $V -trustcacerts -noprompt -file ${SERVICE_FILENAME}_signed.cer -alias "${SERVICE_ALIAS}" -keystore ${SERVICE_KEYSTORE}.p12 -storepass ${SERVICE_PASSWORD} -storetype PKCS12

###

cp -v ${SERVICE_KEYSTORE}.p12 ${SERVICE_KEYSTORE}_one_entry.p12
pkeytool -delete -alias "${ROOT_CA_ALIAS}" -keystore ${SERVICE_KEYSTORE}_one_entry.p12 -storepass ${SERVICE_PASSWORD} -storetype PKCS12
pkeytool -delete -alias "${INTER_CA_ALIAS}" -keystore ${SERVICE_KEYSTORE}_one_entry.p12 -storepass ${SERVICE_PASSWORD} -storetype PKCS12
pkeytool -delete -alias "${SIGNING_CA_ALIAS}" -keystore ${SERVICE_KEYSTORE}_one_entry.p12 -storepass ${SERVICE_PASSWORD} -storetype PKCS12

###

echo "Export service certificate to the PEM format:"
pkeytool -exportcert -alias ${SERVICE_ALIAS} -keystore ${SERVICE_KEYSTORE}.p12 -storetype PKCS12 -storepass ${SERVICE_PASSWORD} -rfc -file ${SERVICE_KEYSTORE}.cer

###

echo "Export service certificate to the PKCS7 format:"
openssl crl2pkcs7 -nocrl -certfile ${SERVICE_FILENAME}.cer -certfile ${SIGNING_CA_FILENAME}.cer -out ${SERVICE_FILENAME}_signing_ca.p7b
openssl crl2pkcs7 -nocrl -certfile ${SERVICE_FILENAME}.cer -certfile ${SIGNING_CA_FILENAME}.cer -certfile ${INTER_CA_FILENAME}.cer -certfile ${ROOT_CA_FILENAME}.cer -out ${SERVICE_FILENAME}_full_chain.p7b

###

echo "Exporting service private key"
echo "TEMP_DIR=$TEMP_DIR"
cat <<EOF >$TEMP_DIR/ExportPrivateKey.java

import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.security.Key;
import java.security.KeyStore;
import java.util.Base64;

public class ExportPrivateKey {
    private File keystoreFile;
    private String keyStoreType;
    private char[] keyStorePassword;
    private char[] keyPassword;
    private String alias;
    private File exportedFile;

    public void export() throws Exception {
        KeyStore keystore = KeyStore.getInstance(keyStoreType);
        keystore.load(new FileInputStream(keystoreFile), keyStorePassword);
        Key key = keystore.getKey(alias, keyPassword);
        String encoded = Base64.getEncoder().encodeToString(key.getEncoded());
        FileWriter fw = new FileWriter(exportedFile);
        fw.write("-----BEGIN PRIVATE KEY-----");
        for (int i = 0; i < encoded.length(); i++) {
            if (((i % 64) == 0) && (i != (encoded.length() - 1))) {
                fw.write("\n");
            }
            fw.write(encoded.charAt(i));
        }
        fw.write("\n");
        fw.write("-----END PRIVATE KEY-----\n");
        fw.close();
    }

    public static void main(String args[]) throws Exception {
        ExportPrivateKey export = new ExportPrivateKey();
        export.keystoreFile = new File(args[0]);
        export.keyStoreType = args[1];
        export.keyStorePassword = args[2].toCharArray();
        export.alias = args[3];
        export.keyPassword = args[4].toCharArray();
        export.exportedFile = new File(args[5]);
        export.export();
    }
}
EOF
echo "cat returned $?"
javac ${TEMP_DIR}/ExportPrivateKey.java
echo "javac returned $?"
java -cp ${TEMP_DIR} ExportPrivateKey ${SERVICE_KEYSTORE}.p12 PKCS12 ${SERVICE_PASSWORD} ${SERVICE_ALIAS} ${SERVICE_PASSWORD} ${SERVICE_KEYSTORE}.pkcs8
echo "java returned $?"
rm ${TEMP_DIR}/ExportPrivateKey.java ${TEMP_DIR}/ExportPrivateKey.class

###

cat ${SERVICE_FILENAME}.cer ${SIGNING_CA_FILENAME}.cer ${INTER_CA_FILENAME}.cer ${ROOT_CA_FILENAME} > ${SERVICE_FILENAME}_full_chain.cer
cat ${SERVICE_FILENAME}.cer ${SIGNING_CA_FILENAME}.cer ${INTER_CA_FILENAME}.cer ${ROOT_CA_FILENAME} ${SERVICE_KEYSTORE}.pkcs8 > ${SERVICE_FILENAME}_full_chain_private_key.cer

###

echo "List the root CA keystore:"
pkeytool -list $V -keystore ${ROOT_CA_FILENAME}.keystore.p12 -keypass ${ROOT_CA_PASSWORD} -storepass ${ROOT_CA_PASSWORD} -storetype PKCS12

echo "List the internal CA keystore:"
pkeytool -list $V -keystore ${INTER_CA_FILENAME}.keystore.p12 -keypass ${INTER_CA_PASSWORD} -storepass ${INTER_CA_PASSWORD} -storetype PKCS12

echo "List the signing CA keystore:"
pkeytool -list $V -keystore ${SIGNING_CA_FILENAME}.keystore.p12 -keypass ${SIGNING_CA_PASSWORD} -storepass ${SIGNING_CA_PASSWORD} -storetype PKCS12

echo "List the service keystore:"
pkeytool -list $V -keystore ${SERVICE_KEYSTORE}.p12 -keypass ${SERVICE_PASSWORD} -storepass ${SERVICE_PASSWORD} -storetype PKCS12

echo "Done"
ls -l ${OUTPUT_DIR}
