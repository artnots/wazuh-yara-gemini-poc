rule Wazuh_Lab_Test
{
    meta:
        description = "Benign test rule for validating the Wazuh and YARA integration"
    strings:
        $marker = "WAZUH_YARA_LAB_TEST"
    condition:
        $marker
}
