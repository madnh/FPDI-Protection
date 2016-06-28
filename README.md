#FPDI-Protection
Composer version of [Setasign FPDI-Protection](https://www.setasign.com/products/fpdi/downloads/) and [FPDF Protection script](http://www.fpdf.org/en/script/script37.php)

#Install
```
composer require madnh/fpdi-protection
```

#USAGE
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

$pdf->SetProtection(FPDI_Protection::FULL_PERMISSIONS);
//$pdf->SetProtection(FPDI_Protection::FULL_PERMISSIONS, '123456');
//$pdf->SetProtection(FPDI_Protection::FULL_PERMISSIONS, '123456', 'ABCDEF');

$pdf->Output($dest_file, 'F');
```