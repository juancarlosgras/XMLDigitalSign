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
    public static function singDocument($xmlDocument, $privateKeyfilename, $password, $serial)
    {
        $certs = array();
        if (!openssl_pkcs12_read(file_get_contents($privateKeyfilename), $certs, $password)) {
            throw new Exception(openssl_error_string());
        } else {
            if (!array_key_exists("pkey", $certs) || !$certs["pkey"]) {
                throw new Exception("No private key found in p12 file.");
            }
            $privateKey = openssl_pkey_get_private($certs["pkey"]);
            if (!$privateKey) {
                throw new Exception("Unable to load private key in ");
            }
            if (!array_key_exists("cert", $certs) || !$certs["cert"]) {
                throw new Exception("No public key found in p12 file.");
            }
            $publicKey = $certs["cert"];
            if (!$publicKey) {
                throw new Exception("Unable to load public key in ");
            }
            $xmlTool = new XmlseclibsAdapter();
            $xmlTool->setPrivateKey($privateKey);
            $xmlTool->setPublicKey($publicKey);
            $xmlTool->addTransform(XmlseclibsAdapter::ENVELOPED);
            $xmlTool->sign($xmlDocument, $serial);
            return $xmlDocument;
        }
    }

    public static function verifyInvoiceSingPublic($xmlDocument, $publicKey)
    {
        $xmlTool = new XmlseclibsAdapter();
        $xmlTool->setPublicKey($publicKey);
        return $xmlTool->verify($xmlDocument);
    }

    public static function verifyInvoiceSingPrivate($xmlDocument, $privateKeyfilename, $password)
    {
        $certs = array();
        if (!openssl_pkcs12_read(file_get_contents($privateKeyfilename), $certs, $password)) {
            throw new Exception(openssl_error_string());
        } else {
            if (!array_key_exists("cert", $certs) || !$certs["cert"]) {
                throw new Exception("No public key found in p12 file.");
            }
            $publicKey = $certs["cert"];
            if (!$publicKey) {
                throw new Exception("Unable to load public key in ");
            }
            return UBLDigSigner::verifyInvoiceSingPublic($xmlDocument, $publicKey);
        }
    }
}