<?php

namespace XmlDigitalSignature\XmlDSig;

use App\Library\XmlDSig\Adapter\XmlseclibsAdapter;
use DOMDocument;
use Exception;

require('AdapterInterface.php');
require('XmlseclibsAdapter.php');
require('RobRichards/XMLSecurityKey.php');
require('RobRichards/XMLSecurityDSig.php');

class UBLDigSigner
{
    /**
     * Sign an UBL document
     *
     *
     * @param DOMDocument $xmlDocument XML-UBL Document
     * @param string $privateKeyfilename Complete path to *.pfx file
     * @param string $password Key of *.pfx file
     * @param string $serial Serial Number of the ULB document
     *
     * @return DOMDocument an `xmlDocument` signed
     * @throws RuntimeException If is not possible load the signature
     */
    public static function signDocument($xmlDocument, $privateKeyfilename, $password, $serial)
    {
        $certs = array();
        if (!openssl_pkcs12_read(file_get_contents($privateKeyfilename), $certs, $password)) {
            throw new RuntimeException(openssl_error_string());
        } else {
            if (!array_key_exists("pkey", $certs) || !$certs["pkey"]) {
                throw new RuntimeException("No private key found in p12 file.");
            }
            $privateKey = openssl_pkey_get_private($certs["pkey"]);
            if (!$privateKey) {
                throw new RuntimeException("Unable to load private key in ");
            }
            if (!array_key_exists("cert", $certs) || !$certs["cert"]) {
                throw new RuntimeException("No public key found in p12 file.");
            }
            $publicKey = $certs["cert"];
            if (!$publicKey) {
                throw new RuntimeException("Unable to load public key in ");
            }
            $xmlTool = new XmlseclibsAdapter();
            $xmlTool->setPrivateKey($privateKey);
            $xmlTool->setPublicKey($publicKey);
            $xmlTool->addTransform(XmlseclibsAdapter::ENVELOPED);
            $xmlTool->sign($xmlDocument, $serial);
            return $xmlDocument;
        }
    }

    /**
     * Check the integrity of a signed document using the pubic key.
     *
     *
     * @param DOMDocument $xmlDocument XML-UBL Document
     * @param string $publicKey Content of the public key
     *
     * @return bool TRUE if is correct or FALSE otherwise
     */
    public static function verifySignatureByPublicKey($xmlDocument, $publicKey)
    {
        $xmlTool = new XmlseclibsAdapter();
        $xmlTool->setPublicKey($publicKey);
        return $xmlTool->verify($xmlDocument);
    }

    /**
     * Check the integrity of a signed document using the private key.
     *
     *
     * @param DOMDocument $xmlDocument XML-UBL Document
     * @param string $privateKeyfilename Complete path to *.pfx file
     * @param string $password Key of *.pfx file
     *
     * @return bool TRUE if is correct or FALSE otherwise
     * @throws RuntimeException If is not possible do the verification
     */
    public static function verifySignatureByPrivateKey($xmlDocument, $privateKeyfilename, $password)
    {
        $certs = array();
        if (!openssl_pkcs12_read(file_get_contents($privateKeyfilename), $certs, $password)) {
            throw new RuntimeException(openssl_error_string());
        } else {
            if (!array_key_exists("cert", $certs) || !$certs["cert"]) {
                throw new RuntimeException("No public key found in p12 file.");
            }
            $publicKey = $certs["cert"];
            if (!$publicKey) {
                throw new RuntimeException("Unable to load public key");
            }
            return UBLDigSigner::verifySignatureByPublicKey($xmlDocument, $publicKey);
        }
    }
}