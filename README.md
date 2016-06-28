# FPDI-Protection
Composer version of [Setasign FPDI-Protection](https://www.setasign.com/products/fpdi/downloads/) and [FPDF Protection script](http://www.fpdf.org/en/script/script37.php)

This script allows to protect the PDF, that is to say prevent people from copying its content, print it or modify it.

## Install
```
composer require madnh/fpdi-protection
```

## USAGE
```
SetProtection([number permissions [, string user_pass [, string owner_pass]]])
```

- permissions: the set of permissions. Empty by default (only viewing is allowed).
- user_pass: user password. Empty by default.
- owner_pass: owner password. If not specified, a random value is used.

### Permissions
The permission array contains values taken from the following list:

- **FPDI_Protection::CAN_PRINT**: print the document
- **FPDI_Protection::CAN_MODIFY**: modify it (except for annotations and forms)
- **FPDI_Protection::CAN_COPY**: copy text and images to the clipboard
- **FPDI_Protection::CAN_ANNOT_FORMS**: add annotations and forms

## Example
```php
$src_file = 'source.pdf';
$dest_file = 'protected.pdf';

$pdf = new \FPDI_Protection();
$pagecount = $pdf->setSourceFile($src_file);

for ($loop = 1; $loop <= $pagecount; $loop++) {
    $tplidx = $pdf->importPage($loop);
    $pdf->addPage();
    $pdf->useTemplate($tplidx);
}

$pdf->SetProtection(\FPDI_Protection::FULL_PERMISSIONS);
//$pdf->SetProtection(\FPDI_Protection::FULL_PERMISSIONS, '123456');
//$pdf->SetProtection(\FPDI_Protection::FULL_PERMISSIONS, '123456', 'ABCDEF');

$pdf->Output($dest_file, 'F');
```

# IMPORTANT
Some PDF readers like Firefox ignore the protection settings, which strongly reduces the usefulness of this script.