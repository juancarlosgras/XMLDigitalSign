# XMLDigitalSign

Module for digital signature of XML-UBL ([Universal Business Language](
https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=ubl)) files.

## Signing a document
You must have a `*.pfx` file and its respective access key. Then you must create an `XML DOMDocument` and use the `signDocument` functionality of the `UBLDigSigner` class.
```php
$fileName = "/file.pfx";
$certKey = "****";

$domXml = new DOMDocument;
$domXml->preserveWhiteSpace = false;
$domXml->loadXML($plainXml);
$documentSerial = "BMX3-325";

$xmlSigned = UBLDigSigner::signDocument($domXml, $fileName, $certKey, $documentSerial);
```
## Verifying the document integrity
To check if a document it's correctly signed (It has not changed since it was signed), you can use `verifySignatureByPublicKey` function or `verifySignatureByPrivateKey` function.