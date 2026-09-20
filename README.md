# wazuh-yara-gemini-poc
Structure Repository
wazuh-yara-gemini-poc/
├── active-response/
│   ├── yara-active-response.py     # Skrip Python utama (Active Response Wrapper)
│   └── requirements.txt            # Dependency Python (misal: google-genai)
├── yara-rules/
│   └── lab-test.yar               # File sampel aturan YARA
├── wazuh-config/
│   ├── local_rules.xml             # Rules Wazuh (Rule 100300 & 100301)
│   ├── local_decoder.xml           # Decoder kustom untuk memproses log YARA
│   └── ossec_snippet.xml           # Potongan konfigurasi <command> & <active-response>
├── README.md                       # Dokumentasi singkat cara instalasi & link ke Medium
└── LICENSE                         # Lisensi open-source (misal: MIT)
