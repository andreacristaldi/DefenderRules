# DefenderRules
Tool designed to parse and analyze Microsoft Defender AV signature definition files 

# Description
DefenderRules is a tool designed to parse and analyze Microsoft Defender signature definition files (extracted from .vdm using tools like DefenderDecompress). It extracts metadata about threats, parses rule types, and generates:

A list of discovered threats
Missing threat definitions
Statistical breakdown of signature types
Interactive charts for analysis

# Requirements
.NET Core or .NET Framework (compatible with C# 8.0+)

Windows Defender installed

PowerShell access (for retrieving threat catalog via Get-MpThreatCatalog)



# Usage
DefenderRules.exe <ExtractedFilePath> <OutputDirectory>

you can use RunMe2.bat (please config path and referement)

# Example
DefenderRules.exe mpasbase.vdm.decompressed ./output

This will:

Load the defender.csv threat catalog (auto-downloads via PowerShell if missing)

Extract all threat entries from the Defender binary

Save binary rule data into individual files

Output logs, statistics, and two HTML dashboards

Output:

| File Name                     | Description                                          |
| ----------------------------- | ---------------------------------------------------- |
| `output.txt`                  | List of all identified threat entries                |
| `missing.txt`                 | Threats found in catalog but not in binary           |
| `ThreatsStats.csv`            | Threat-by-threat signature type counts               |
| `ThreatsGlobalStats.csv`      | Total signature type usage across all threats        |
| `Top30GlobalStatsChart.html`  | Interactive bar chart of most common signature types |
| `ThreatGroupStatsCharts.html` | Grouped charts by threat category                    |
| `<ThreatName>.bin`            | Binary data for each threat rule                     |


# Disclaimer
This tool is intended for educational and security analysis purposes only.
Improper use may violate Microsoft's license agreements. Use responsibly and only on systems you own or are authorized to analyze.

# Author
Project: Andrea Cristaldi <a href="https://www.linkedin.com/in/andreacristaldi/" target="blank_">Linkedin</a>, <a href="https://www.cybersec4.com" target="blank_">Cybersec4</a>

# License
This project is licensed under the MIT License.


