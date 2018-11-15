# XMLDigitalSign

Module for digital signature of XML-UBL ([Universal Business Language](
https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=ubl)) files.

## How to use
You must have a `*.pfx` file and its respective access key. Then you must create an `XML DOMDocument` and use the `singDocument` functionality of the `UBLDigSigner` class.
```php
$fileName = "/file.pfx";
$certKey = "****";

$domXml = new DOMDocument;
$domXml->preserveWhiteSpace = false;
$domXml->loadXML($plainXml);
$documentSerial = "BMX3-325";

$xmlSigned = UBLDigSigner::singDocument($domXml, $fileName, $certKey, $documentSerial);
```
