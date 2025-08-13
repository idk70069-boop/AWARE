rule AWARE_EICAR_Test
{
    meta:
        description = "Detects the EICAR test string"
        author = "AWARE"
        severity = "low"
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    condition:
        $eicar
}