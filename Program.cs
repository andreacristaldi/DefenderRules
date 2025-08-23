// DefenderRules
// Author: Andrea Cristaldi 2025 - https://github.com/andreacristaldi/DefenderRules
// This project is licensed under the MIT License.

using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection.Emit;
using System.Text;
using System.Text.RegularExpressions;


public class DefenderRules
{
    public struct STRUCT_SIG_TYPE_THREAT_BEGIN
    {
        public byte ui8SignatureType;
        public byte ui8SizeLow;
        public ushort ui16SizeHigh;
        public uint ui32SignatureId;
        public byte[] unknownBytes1;
        public byte ui8SizeThreatName;
        public byte[] unknownBytes2;
        public string lpszThreatName;
        public byte[] unknownBytes3;
    }

    public struct STRUCT_SIG_TYPE_THREAT_END
    {
        public byte ui8SignatureType;
        public byte ui8SizeLow;
        public ushort ui16SizeHigh;
        public byte[] pbRuleContent;
    }

    public class Threat
    {
        public string ThreatName { get; set; }
        public long BeginPosition { get; set; }
        public long EndPosition { get; set; }
        public Dictionary<string, long> SignatureStats { get; set; } = new Dictionary<string, long>();

    }

    private static readonly Dictionary<uint, Threat> Threats = new Dictionary<uint, Threat>();


    private static readonly Dictionary<string, string> ThreatDictionary = new Dictionary<string, string>
    {

    };



    public static void Main(string[] args)
    {
        string filePath = "";
        string outputDirectory = "";
        Console.WriteLine("DefenderRules\nhttps://github.com/andreacristaldi/DefenderRules\n\n");

        if (args.Length != 2)
        {
            Console.WriteLine("Usage: DefenderRules <FilePath> <OutputDirectory>");
            return;
        }

        filePath = args[0];
        outputDirectory = args[1];

        if (!File.Exists(filePath))
        {
            Console.WriteLine($"{filePath} does not exist.");
            return;
        }

        ReadCSV();

        ExtractThreatSignatures(filePath, outputDirectory);
    }

    public static void ExtractThreatSignatures(string filePath, string outputDirectory)
    {
        Console.WriteLine("Searching...");
        uint ui32SignatureId = 0;

        using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
        {
            using (BinaryReader reader = new BinaryReader(fs))
            {
                while (reader.BaseStream.Position != reader.BaseStream.Length)
                {


                    try
                    {
                        long beginPosition = reader.BaseStream.Position;

                        string Signaturetype = GetSignatureType(reader.ReadByte());
                        if (Signaturetype == "SIGNATURE_TYPE_THREAT_BEGIN")
                        {

                            byte ui8SizeLow = reader.ReadByte();
                            ushort ui16SizeHigh = reader.ReadUInt16();
                            int Size = ui8SizeLow | (ui16SizeHigh << 8);
                            long endPosition = reader.BaseStream.Position + Size;

                            

                            ui32SignatureId = reader.ReadUInt32();

                            if (ThreatDictionary.ContainsKey(ui32SignatureId.ToString()))
                            {

                                byte[] unknownBytes1 = reader.ReadBytes(6);
                                byte ui8SizeThreatName = reader.ReadByte();
                                byte[] unknownBytes2 = reader.ReadBytes(1); 

                                string lpszThreatName = Encoding.ASCII.GetString(reader.ReadBytes(ui8SizeThreatName));
                                byte[] unknownBytes3 = reader.ReadBytes(9);
                                
                                
                                if (!Threats.ContainsKey(ui32SignatureId))
                                {
                                    Threats[ui32SignatureId] = new Threat
                                    {

                                        ThreatName = ThreatDictionary[ui32SignatureId.ToString()],
                                        BeginPosition = beginPosition
                                    };
                                    Console.Write(".");
                                }


                            }
                            else
                            {


                            }


                            reader.BaseStream.Position = endPosition;

                        }
                        else if (Signaturetype == "SIGNATURE_TYPE_THREAT_END")
                        {

                            
                            byte ui8SizeLow = reader.ReadByte();
                            ushort ui16SizeHigh = reader.ReadUInt16();
                            int Size = ui8SizeLow | (ui16SizeHigh << 8);
                            long endPosition = reader.BaseStream.Position + Size;
                            byte[] pbRuleContent = reader.ReadBytes(4);

                            uint pbRuleContentId = BitConverter.ToUInt32(pbRuleContent, 0);

                            
                            string signatureIdStr = pbRuleContentId.ToString();


                            
                            if (Threats.ContainsKey(pbRuleContentId))
                            {
                                if (Threats[pbRuleContentId].EndPosition == 0)
                                {
                                    Threats[pbRuleContentId].EndPosition = endPosition;
                                    

                                }



                            }

                            
                            reader.BaseStream.Position = endPosition;
                            ui32SignatureId = 0;

                        }


                        else if (Signaturetype != "SIGNATURE_TYPE_UNKNOWN")
                        {
                            

                            byte ui8SizeLow = reader.ReadByte();
                            ushort ui16SizeHigh = reader.ReadUInt16();
                            int Size = ui8SizeLow | (ui16SizeHigh << 8);
                            long endPosition = reader.BaseStream.Position + Size;
                            
                            if (Threats.ContainsKey(ui32SignatureId))
                            {
                                if (!Threats[ui32SignatureId].SignatureStats.ContainsKey(Signaturetype))
                                {
                                    Threats[ui32SignatureId].SignatureStats[Signaturetype] = 1;


                                }
                                else
                                {
                                    Threats[ui32SignatureId].SignatureStats[Signaturetype]++;
                                }



                            }




                            reader.BaseStream.Position = endPosition;

                        }

                        else
                        {
                            reader.BaseStream.Position = reader.BaseStream.Position + 1;
                        }
                    }




                    catch (EndOfStreamException)
                    {
                        break;
                    }

                }
            }
        }
        Console.WriteLine("\n\nThreats:");
        Console.WriteLine(Threats.Count);

        Console.WriteLine("\n\nSaving logs...");
        SaveThreatsToFile(Threats, outputDirectory + "\\" + "output.txt");
        SaveMissingThreatsToFile(Threats, ThreatDictionary, outputDirectory + "\\" + "missing.txt");

        Console.WriteLine("\n\nSaving stats...");
        SaveStats(outputDirectory);

        Console.WriteLine("\n\nSaving signatures to output path...");
        foreach (var threatEntry in Threats)
        {
            uint key = threatEntry.Key;
            Threat threat = threatEntry.Value;

           
            SaveRuleContent(filePath, threat.BeginPosition, threat.EndPosition, outputDirectory + "\\" + threat.ThreatName.Replace("/", "_").Replace(":", "_") + ".bin");
            Console.Write(".");


        }




    }

    public static void SaveStats(string outputDirectory)
    {
        var allKeys = Threats.Values.SelectMany(t => t.SignatureStats.Keys).Distinct().OrderBy(k => k).ToList();

        using (var writer = new StreamWriter(outputDirectory + "\\ThreatsStats.csv"))
        {
            writer.Write("ThreatName");
            foreach (var key in allKeys)
            {
                writer.Write($",{key}");
            }
            writer.WriteLine();

            foreach (var threat in Threats.Values)
            {
                writer.Write(threat.ThreatName);
                foreach (var key in allKeys)
                {
                    writer.Write(",");
                    if (threat.SignatureStats.ContainsKey(key))
                    {
                        writer.Write(threat.SignatureStats[key]);
                    }
                    else
                    {
                        writer.Write("0");
                    }
                }
                writer.WriteLine();
            }
        }

        var globalSums = new Dictionary<string, long>();
        foreach (var key in allKeys)
        {
            globalSums[key] = Threats.Values.Sum(t => t.SignatureStats.ContainsKey(key) ? t.SignatureStats[key] : 0);
        }

        using (var writer = new StreamWriter(outputDirectory + "\\ThreatsGlobalStats.csv"))
        {
            writer.WriteLine(string.Join(",", allKeys));

            writer.WriteLine(string.Join(",", allKeys.Select(key => globalSums[key])));
        }

        var top30GlobalSums = globalSums.OrderByDescending(kvp => kvp.Value).Take(30).ToList();

        var headers = top30GlobalSums.Select(kvp => kvp.Key).ToList();
        var values = top30GlobalSums.Select(kvp => kvp.Value).ToList();

        string strHeaders = "[";

        foreach (var el in headers)
        {
            strHeaders = strHeaders + "'" + el + "',";

        }
        strHeaders = strHeaders.Substring(0, strHeaders.Length - 1) + "]";

        string strValues = "[";

        foreach (var el in values)
        {
            strValues = strValues + el + ",";

        }
        strValues = strValues.Substring(0, strValues.Length - 1) + "]";




        var htmlContent = $@"
<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset='UTF-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
    <title>DefenderRules Charts</title>
    <script src='https://cdn.jsdelivr.net/npm/chart.js'></script>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 20px;
        }}
        canvas {{
            margin-top: 20px;
        }}
    </style>
</head>
<body>
    <h1>DefenderRules - Top 30 Global Threats Signatures Stats Chart</h1>
    <canvas id='globalSumsChart'></canvas>

    <script>
        document.addEventListener('DOMContentLoaded', function() {{
            const headers = {strHeaders};
            const values = {strValues};

            function createGlobalSumsChart(headers, values) {{
                const ctx = document.getElementById('globalSumsChart').getContext('2d');

                new Chart(ctx, {{
                    type: 'bar',
                    data: {{
                        labels: headers,
                        datasets: [{{
                            label: 'Global Sums',
                            data: values,
                            backgroundColor: getRandomColor()
                        }}]
                    }},
                    options: {{
                        responsive: true,
                        scales: {{
                            y: {{
                                beginAtZero: true
                            }}
                        }}
                    }}
                }});
            }}

            function getRandomColor() {{
                const r = Math.floor(Math.random() * 255);
                const g = Math.floor(Math.random() * 255);
                const b = Math.floor(Math.random() * 255);
                return `rgba(${{r}}, ${{g}}, ${{b}}, 0.6)`;
            }}

            createGlobalSumsChart(headers, values);
        }});
    </script>
</body>
</html>";


        File.WriteAllText(outputDirectory + "\\Top30GlobalStatsChart.html", htmlContent);



        var groupedThreats = Threats.Values.GroupBy(t => t.ThreatName.Split(':')[0])
                                           .OrderBy(g => g.Key)
                                           .ToDictionary(g => g.Key, g => g.ToList());



        var groupedSums = new Dictionary<string, Dictionary<string, long>>();
        foreach (var group in groupedThreats)
        {
            var groupName = group.Key;
            var signatureStatsSums = new Dictionary<string, long>();
            foreach (var threat in group.Value)
            {
                foreach (var stat in threat.SignatureStats)
                {
                    if (!signatureStatsSums.ContainsKey(stat.Key))
                    {
                        signatureStatsSums[stat.Key] = 0;
                    }
                    signatureStatsSums[stat.Key] += stat.Value;
                }
            }




            groupedSums[groupName] = signatureStatsSums.OrderByDescending(kvp => kvp.Value)
                                                       .Take(10)
                                                       .ToDictionary(kvp => kvp.Key, kvp => kvp.Value);
        }


        var htmlContent2 = new StringBuilder();
        htmlContent2.AppendLine(@"
<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset='UTF-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
    <title>DefenderRules Charts</title>
    <script src='https://cdn.jsdelivr.net/npm/chart.js'></script>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 20px;
        }
        canvas {
            margin-top: 20px;
        }
    </style>
</head>
<body>
    <h1>DefenderRules - Threat Groups Top 10 Signatures Stats Chart</h1>");

        foreach (var group in groupedSums)
        {
            var headers2 = group.Value.Keys.ToList();
            var values2 = group.Value.Values.ToList();
            var groupName = group.Key;


            string strHeaders2 = "[";

            foreach (var el in headers2)
            {
                strHeaders2 = strHeaders2 + "'" + el + "',";

            }
            strHeaders2 = strHeaders2.Substring(0, strHeaders2.Length - 1) + "]";

            string strValues2 = "[";

            foreach (var el in values2)
            {
                strValues2 = strValues2 + el + ",";

            }
            strValues2 = strValues2.Substring(0, strValues2.Length - 1) + "]";




            htmlContent2.AppendLine($@"
    <h2>{groupName}</h2>
    <canvas id='{groupName}Chart'></canvas>
    <script>
        document.addEventListener('DOMContentLoaded', function() {{
            const headers = {strHeaders2};
            const values = {strValues2};

            function createChart(ctx, headers, values) {{
                new Chart(ctx, {{
                    type: 'bar',
                    data: {{
                        labels: headers,
                        datasets: [{{
                            label: '{groupName} Sums',
                            data: values,
                            backgroundColor: getRandomColor()
                        }}]
                    }},
                    options: {{
                        responsive: true,
                        scales: {{
                            y: {{
                                beginAtZero: true
                            }}
                        }}
                    }}
                }});
            }}

            function getRandomColor() {{
                const r = Math.floor(Math.random() * 255);
                const g = Math.floor(Math.random() * 255);
                const b = Math.floor(Math.random() * 255);
                return `rgba(${{r}}, ${{g}}, ${{b}}, 0.6)`;
            }}

            const ctx = document.getElementById('{groupName}Chart').getContext('2d');
            createChart(ctx, headers, values);
        }});
    </script>");
        }

        htmlContent2.AppendLine(@"
</body>
</html>");



        File.WriteAllText(outputDirectory + "\\ThreatGroupStatsCharts.html", htmlContent2.ToString());







    }

    static string GetSignatureType(uint a1)
    {
        if (a1 <= 0x9D)
        {
            if (a1 == 157)
                return "SIGNATURE_TYPE_THREAD_X86";
            if (a1 > 0x6A)
            {
                if (a1 > 0x86)
                {
                    if (a1 > 0x90)
                    {
                        switch (a1)
                        {
                            case 0x91:
                                return "SIGNATURE_TYPE_VDLL_IA64";
                            case 0x95:
                                return "SIGNATURE_TYPE_PEBMPAT";
                            case 0x96:
                                return "SIGNATURE_TYPE_AAGGREGATOR";
                            case 0x97:
                                return "SIGNATURE_TYPE_SAMPLE_REQUEST_BY_NAME";
                            case 0x98:
                                return "SIGNATURE_TYPE_REMOVAL_POLICY_BY_NAME";
                            case 0x99:
                                return "SIGNATURE_TYPE_TUNNEL_X86";
                            case 0x9A:
                                return "SIGNATURE_TYPE_TUNNEL_X64";
                            case 0x9B:
                                return "SIGNATURE_TYPE_TUNNEL_IA64";
                            case 0x9C:
                                return "SIGNATURE_TYPE_VDLL_ARM";
                        }
                    }
                    else
                    {
                        switch (a1)
                        {
                            case 0x90:
                                return "SIGNATURE_TYPE_TARGET_SCRIPT_PCODE";
                            case 0x87:
                                return "SIGNATURE_TYPE_PESTATIC";
                            case 0x88:
                                return "SIGNATURE_TYPE_UFSP_DISABLE";
                            case 0x89:
                                return "SIGNATURE_TYPE_FOPEX";
                            case 0x8A:
                                return "SIGNATURE_TYPE_PEPCODE";
                            case 0x8B:
                                return "SIGNATURE_TYPE_IL_PATTERN";
                            case 0x8C:
                                return "SIGNATURE_TYPE_ELFHSTR_EXT";
                            case 0x8D:
                                return "SIGNATURE_TYPE_MACHOHSTR_EXT";
                            case 0x8E:
                                return "SIGNATURE_TYPE_DOSHSTR_EXT";
                            case 0x8F:
                                return "SIGNATURE_TYPE_MACROHSTR_EXT";
                        }
                    }
                }
                else
                {
                    if (a1 == 134)
                        return "SIGNATURE_TYPE_PEMAIN_LOCATOR";
                    if (a1 > 0x79)
                    {
                        switch (a1)
                        {
                            case 0x7A:
                                return "SIGNATURE_TYPE_VERSIONCHECK";
                            case 0x7B:
                                return "SIGNATURE_TYPE_SAMPLE_REQUEST";
                            case 0x7C:
                                return "SIGNATURE_TYPE_VDLL_X64";
                            case 0x7E:
                                return "SIGNATURE_TYPE_SNID";
                            case 0x7F:
                                return "SIGNATURE_TYPE_FOP";
                            case 0x80:
                                return "SIGNATURE_TYPE_KCRCE";
                            case 0x83:
                                return "SIGNATURE_TYPE_VFILE";
                            case 0x84:
                                return "SIGNATURE_TYPE_SIGFLAGS";
                            case 0x85:
                                return "SIGNATURE_TYPE_PEHSTR_EXT2";
                        }
                    }
                    else
                    {
                        switch (a1)
                        {
                            case 'y':
                                return "SIGNATURE_TYPE_VDLL_X86";
                            case 'k':
                                return "SIGNATURE_TYPE_WVT_EXCEPTION";
                            case 'l':
                                return "SIGNATURE_TYPE_REVOKED_CERTIFICATE";
                            case 'p':
                                return "SIGNATURE_TYPE_TRUSTED_PUBLISHER";
                            case 'q':
                                return "SIGNATURE_TYPE_ASEP_FILEPATH";
                            case 's':
                                return "SIGNATURE_TYPE_DELTA_BLOB";
                            case 't':
                                return "SIGNATURE_TYPE_DELTA_BLOB_RECINFO";
                            case 'u':
                                return "SIGNATURE_TYPE_ASEP_FOLDERNAME";
                            case 'w':
                                return "SIGNATURE_TYPE_PATTMATCH_V2";
                            case 'x':
                                return "SIGNATURE_TYPE_PEHSTR_EXT";
                        }
                    }
                }
            }
            else
            {
                if (a1 == 106)
                    return "SIGNATURE_TYPE_REMOVAL_POLICY";
                if (a1 > 0x4A)
                {
                    if (a1 > 0x5D)
                    {
                        switch (a1)
                        {
                            case '^':
                                return "SIGNATURE_TYPE_FILENAME";
                            case '_':
                                return "SIGNATURE_TYPE_FILEPATH";
                            case '`':
                                return "SIGNATURE_TYPE_FOLDERNAME";
                            case 'a':
                                return "SIGNATURE_TYPE_PEHSTR";
                            case 'b':
                                return "SIGNATURE_TYPE_LOCALHASH";
                            case 'c':
                                return "SIGNATURE_TYPE_REGKEY";
                            case 'd':
                                return "SIGNATURE_TYPE_HOSTSENTRY";
                            case 'g':
                                return "SIGNATURE_TYPE_STATIC";
                            case 'i':
                                return "SIGNATURE_TYPE_LATENT_THREAT";
                        }
                    }
                    else
                    {
                        switch (a1)
                        {
                            case ']':
                                return "SIGNATURE_TYPE_THREAT_END";
                            case 'P':
                                return "SIGNATURE_TYPE_CKSIMPLEREC";
                            case 'Q':
                                return "SIGNATURE_TYPE_PATTMATCH";
                            case 'S':
                                return "SIGNATURE_TYPE_RPFROUTINE";
                            case 'U':
                                return "SIGNATURE_TYPE_NID";
                            case 'V':
                                return "SIGNATURE_TYPE_GENSFX";
                            case 'W':
                                return "SIGNATURE_TYPE_UNPLIB";
                            case 'X':
                                return "SIGNATURE_TYPE_DEFAULTS";
                            case '[':
                                return "SIGNATURE_TYPE_DBVAR";
                            case '\\':
                                return "SIGNATURE_TYPE_THREAT_BEGIN";
                        }
                    }
                }
                else
                {
                    if (a1 == 74)
                        return "SIGNATURE_TYPE_TARGET_SCRIPT";
                    if (a1 > 0x2C)
                    {
                        switch (a1)
                        {
                            case '0':
                                return "SIGNATURE_TYPE_TITANFLT";
                            case '=':
                                return "SIGNATURE_TYPE_PEFILE_CURE";
                            case '>':
                                return "SIGNATURE_TYPE_MAC_CURE";
                            case '@':
                                return "SIGNATURE_TYPE_SIGTREE";
                            case 'A':
                                return "SIGNATURE_TYPE_SIGTREE_EXT";
                            case 'B':
                                return "SIGNATURE_TYPE_MACRO_PCODE";
                            case 'C':
                                return "SIGNATURE_TYPE_MACRO_SOURCE";
                            case 'D':
                                return "SIGNATURE_TYPE_BOOT";
                            case 'I':
                                return "SIGNATURE_TYPE_CLEANSCRIPT";
                        }
                    }
                    else
                    {
                        switch (a1)
                        {
                            case 0x2C:
                                return "SIGNATURE_TYPE_NSCRIPT_CURE";
                            case 1:
                                return "SIGNATURE_TYPE_RESERVED";
                            case 2:
                                return "SIGNATURE_TYPE_VOLATILE_THREAT_INFO";
                            case 3:
                                return "SIGNATURE_TYPE_VOLATILE_THREAT_ID";
                            case 0x11:
                                return "SIGNATURE_TYPE_CKOLDREC";
                            case 0x20:
                                return "SIGNATURE_TYPE_KVIR32";
                            case 0x21:
                                return "SIGNATURE_TYPE_POLYVIR32";
                            case 0x27:
                                return "SIGNATURE_TYPE_NSCRIPT_NORMAL";
                            case 0x28:
                                return "SIGNATURE_TYPE_NSCRIPT_SP";
                            case 0x29:
                                return "SIGNATURE_TYPE_NSCRIPT_BRUTE";
                        }
                    }
                }
            }
            return "SIGNATURE_TYPE_UNKNOWN";
        }
        if (a1 <= 0xC6)
        {
            if (a1 == 198)
                return "SIGNATURE_TYPE_MSILFOPEX";
            if (a1 > 0xB1)
            {
                if (a1 > 0xBC)
                {
                    switch (a1)
                    {
                        case 0xBD:
                            return "SIGNATURE_TYPE_LUASTANDALONE";
                        case 0xBE:
                            return "SIGNATURE_TYPE_DEXHSTR_EXT";
                        case 0xBF:
                            return "SIGNATURE_TYPE_JAVAHSTR_EXT";
                        case 0xC0:
                            return "SIGNATURE_TYPE_MAGICCODE";
                        case 0xC1:
                            return "SIGNATURE_TYPE_CLEANSTORE_RULE";
                        case 0xC2:
                            return "SIGNATURE_TYPE_VDLL_CHECKSUM";
                        case 0xC3:
                            return "SIGNATURE_TYPE_THREAT_UPDATE_STATUS";
                        case 0xC4:
                            return "SIGNATURE_TYPE_VDLL_MSIL";
                        case 0xC5:
                            return "SIGNATURE_TYPE_ARHSTR_EXT";
                    }
                }
                else
                {
                    switch (a1)
                    {
                        case 0xBC:
                            return "SIGNATURE_TYPE_KPATEX";
                        case 0xB2:
                            return "SIGNATURE_TYPE_VFILEEX";
                        case 0xB3:
                            return "SIGNATURE_TYPE_SIGTREE_BM";
                        case 0xB4:
                            return "SIGNATURE_TYPE_VBFOP";
                        case 0xB5:
                            return "SIGNATURE_TYPE_VDLL_META";
                        case 0xB6:
                            return "SIGNATURE_TYPE_TUNNEL_ARM";
                        case 0xB7:
                            return "SIGNATURE_TYPE_THREAD_ARM";
                        case 0xB8:
                            return "SIGNATURE_TYPE_PCODEVALIDATOR";
                        case 0xBA:
                            return "SIGNATURE_TYPE_MSILFOP";
                        case 0xBB:
                            return "SIGNATURE_TYPE_KPAT";
                    }
                }
            }
            else
            {
                if (a1 == 177)
                    return "SIGNATURE_TYPE_NISBLOB";
                if (a1 > 0xA7)
                {
                    switch (a1)
                    {
                        case 0xA8:
                            return "SIGNATURE_TYPE_BM_INFO";
                        case 0xA9:
                            return "SIGNATURE_TYPE_NDAT";
                        case 0xAA:
                            return "SIGNATURE_TYPE_FASTPATH_DATA";
                        case 0xAB:
                            return "SIGNATURE_TYPE_FASTPATH_SDN";
                        case 0xAC:
                            return "SIGNATURE_TYPE_DATABASE_CERT";
                        case 0xAD:
                            return "SIGNATURE_TYPE_SOURCE_INFO";
                        case 0xAE:
                            return "SIGNATURE_TYPE_HIDDEN_FILE";
                        case 0xAF:
                            return "SIGNATURE_TYPE_COMMON_CODE";
                        case 0xB0:
                            return "SIGNATURE_TYPE_VREG";
                    }
                }
                else
                {
                    switch (a1)
                    {
                        case 0xA7:
                            return "SIGNATURE_TYPE_BM_STATIC";
                        case 0x9E:
                            return "SIGNATURE_TYPE_THREAD_X64";
                        case 0x9F:
                            return "SIGNATURE_TYPE_THREAD_IA64";
                        case 0xA0:
                            return "SIGNATURE_TYPE_FRIENDLYFILE_SHA256";
                        case 0xA1:
                            return "SIGNATURE_TYPE_FRIENDLYFILE_SHA512";
                        case 0xA2:
                            return "SIGNATURE_TYPE_SHARED_THREAT";
                        case 0xA3:
                            return "SIGNATURE_TYPE_VDM_METADATA";
                        case 0xA4:
                            return "SIGNATURE_TYPE_VSTORE";
                        case 0xA5:
                            return "SIGNATURE_TYPE_VDLL_SYMINFO";
                        case 0xA6:
                            return "SIGNATURE_TYPE_IL2_PATTERN";
                    }
                }
            }
            return "SIGNATURE_TYPE_UNKNOWN";
        }
        if (a1 <= 0xDA)
        {
            if (a1 == 218)
                return "SIGNATURE_TYPE_FASTPATH_SDN_EX";
            if (a1 > 0xD0)
            {
                switch (a1)
                {
                    case 0xD1:
                        return "SIGNATURE_TYPE_SWFHSTR_EXT";
                    case 0xD2:
                        return "SIGNATURE_TYPE_REWSIGS";
                    case 0xD3:
                        return "SIGNATURE_TYPE_AUTOITHSTR_EXT";
                    case 0xD4:
                        return "SIGNATURE_TYPE_INNOHSTR_EXT";
                    case 0xD5:
                        return "SIGNATURE_TYPE_CERT_STORE_ENTRY";
                    case 0xD6:
                        return "SIGNATURE_TYPE_EXPLICITRESOURCE";
                    case 0xD7:
                        return "SIGNATURE_TYPE_CMDHSTR_EXT";
                    case 0xD8:
                        return "SIGNATURE_TYPE_FASTPATH_TDN";
                    case 0xD9:
                        return "SIGNATURE_TYPE_EXPLICITRESOURCEHASH";
                }
            }
            else
            {
                switch (a1)
                {
                    case 0xD0:
                        return "SIGNATURE_TYPE_BRUTE";
                    case 0xC7:
                        return "SIGNATURE_TYPE_VBFOPEX";
                    case 0xC8:
                        return "SIGNATURE_TYPE_FOP64";
                    case 0xC9:
                        return "SIGNATURE_TYPE_FOPEX64";
                    case 0xCA:
                        return "SIGNATURE_TYPE_JSINIT";
                    case 0xCB:
                        return "SIGNATURE_TYPE_PESTATICEX";
                    case 0xCC:
                        return "SIGNATURE_TYPE_KCRCEX";
                    case 0xCD:
                        return "SIGNATURE_TYPE_FTRIE_POS";
                    case 0xCE:
                        return "SIGNATURE_TYPE_NID64";
                    case 0xCF:
                        return "SIGNATURE_TYPE_MACRO_PCODE64";
                }
            }
            return "SIGNATURE_TYPE_UNKNOWN";
        }
        if (a1 <= 0xE5)
        {
            switch (a1)
            {
                case 0xE5:
                    return "SIGNATURE_TYPE_SNIDEX";
                case 0xDB:
                    return "SIGNATURE_TYPE_BLOOM_FILTER";
                case 0xDC:
                    return "SIGNATURE_TYPE_RESEARCH_TAG";
                case 0xDE:
                    return "SIGNATURE_TYPE_ENVELOPE";
                case 0xDF:
                    return "SIGNATURE_TYPE_REMOVAL_POLICY64";
                case 0xE0:
                    return "SIGNATURE_TYPE_REMOVAL_POLICY64_BY_NAME";
                case 0xE1:
                    return "SIGNATURE_TYPE_VDLL_META_X64";
                case 0xE2:
                    return "SIGNATURE_TYPE_VDLL_META_ARM";
                case 0xE3:
                    return "SIGNATURE_TYPE_VDLL_META_MSIL";
                case 0xE4:
                    return "SIGNATURE_TYPE_MDBHSTR_EXT";
            }
            return "SIGNATURE_TYPE_UNKNOWN";
        }
        switch (a1)
        {
            case 0xE6:
                return "SIGNATURE_TYPE_SNIDEX2";
            case 0xE7:
                return "SIGNATURE_TYPE_AAGGREGATOREX";
            case 0xE8:
                return "SIGNATURE_TYPE_PUA_APPMAP";
            case 0xE9:
                return "SIGNATURE_TYPE_PROPERTY_BAG";
            case 0xEA:
                return "SIGNATURE_TYPE_DMGHSTR_EXT";
            case 0xEB:
                return "SIGNATURE_TYPE_DATABASE_CATALOG";
        }
        if (a1 != 236)
        {
            if (a1 == 237)
                return "SIGNATURE_TYPE_BM_ENV_VAR_MAP";
            return "SIGNATURE_TYPE_UNKNOWN";
        }
        return "SIGNATURE_TYPE_DATABASE_CERT2";
    }




    static void SaveThreatsToFile(Dictionary<uint, Threat> dictionary, string filePath)
    {
        using (StreamWriter writer = new StreamWriter(filePath))
        {

            foreach (var kvp in dictionary)
            {
                writer.WriteLine($"Key: {kvp.Key}, ThreatName: {kvp.Value.ThreatName}, BeginPosition: {kvp.Value.BeginPosition}, EndPosition: {kvp.Value.EndPosition}");
            }
        }
    }

    static void SaveMissingThreatsToFile(Dictionary<uint, Threat> threats, Dictionary<string, string> threatDictionary, string filePath)
    {
        using (StreamWriter writer = new StreamWriter(filePath))
        {
            foreach (var kvp in threatDictionary)
            {
                uint key;
                if (uint.TryParse(kvp.Key, out key) && !threats.ContainsKey(key))
                {
                    writer.WriteLine($"Key: {kvp.Key}, Description: {kvp.Value}");
                }
            }
        }
    }





    public static void PrintRuleContent(string filePath, long beginPosition, long endPosition)
    {

        using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
        {
            using (BinaryReader reader = new BinaryReader(fs))
            {
                reader.BaseStream.Seek(beginPosition, SeekOrigin.Begin);
                byte[] content = reader.ReadBytes((int)(endPosition - beginPosition));




                long position = beginPosition;
                for (int i = 0; i < content.Length; i += 16)
                {
                    Console.Write($"{position:X8} ");
                    for (int j = 0; j < 16; j++)
                    {
                        if (i + j < content.Length)
                        {
                            Console.Write($"{content[i + j]:X2} ");
                        }
                        else
                        {
                            Console.Write("   ");
                        }
                    }
                    Console.Write(" ");
                    for (int j = 0; j < 16; j++)
                    {
                        if (i + j < content.Length)
                        {
                            byte b = content[i + j];
                            if (b >= 32 && b <= 126)
                            {
                                Console.Write((char)b);
                            }
                            else
                            {
                                Console.Write('.');
                            }
                        }
                        else
                        {
                            Console.Write(' ');
                        }
                    }
                    Console.WriteLine();
                    position += 16;
                }
                Console.WriteLine("\n\n");



            }
        }





    }


    public static void ReadCSV()
    {
        string filePath = "defender.csv";

        if (!File.Exists(filePath))
        {
            Console.WriteLine("Threat dictionary not found. Attempting to retrieve using PowerShell...");

            try
            {
                ProcessStartInfo psi = new ProcessStartInfo()
                {
                    FileName = "powershell.exe",
                    Arguments = "Get-MpThreatCatalog | Export-Csv -Path ./defender.csv -NoTypeInformation",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };

                using (Process process = new Process())
                {
                    process.StartInfo = psi;
                    process.Start();

                    string output = process.StandardOutput.ReadToEnd();
                    string error = process.StandardError.ReadToEnd();

                    process.WaitForExit();

                    if (process.ExitCode != 0 || !File.Exists(filePath))
                    {
                        Console.WriteLine("PowerShell execution failed or defender.csv not created.\n" + error);
                        Console.WriteLine("Ensure PowerShell is available, Windows Defender is installed, and you have sufficient permissions.");
                        return;
                    }

                    Console.WriteLine("Threat catalog successfully retrieved.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error executing PowerShell: " + ex.Message);
                Console.WriteLine("Make sure PowerShell is installed and accessible, and that script execution is not restricted.");
                return;
            }
        }

        if (!File.Exists(filePath))
        {
            Console.WriteLine("Warning: Threat name CSV dictionary (defender.csv) not found.");
            Environment.Exit(1);
            return;
        }




        string[] lines = File.ReadAllLines(filePath);

        for (int i = 1; i < lines.Length; i++)
        {

            string[] fields = SplitCsvLine(lines[i]);

            if (fields.Length >= 4)
            {

                string threatID = fields[2];
                string threatName = fields[3];


                if (!ThreatDictionary.ContainsKey(threatID))
                {
                    ThreatDictionary.Add(threatID, threatName);
                }
            }
        }
    }

    static string[] SplitCsvLine(string line)
    {
        List<string> result = new List<string>();
        bool inQuotes = false;
        string currentField = "";

        foreach (char c in line)
        {
            if (c == '\"')
            {
                inQuotes = !inQuotes;
            }
            else if (c == ',' && !inQuotes)
            {
                result.Add(currentField);
                currentField = "";
            }
            else
            {
                currentField += c;
            }
        }

        if (currentField != "")
        {
            result.Add(currentField);
        }

        return result.ToArray();
    }


    public static void SaveRuleContent(string filePath, long beginPosition, long endPosition, string outputFilePath)
    {
        if (endPosition > beginPosition)
        {
            using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
            {
                using (BinaryReader reader = new BinaryReader(fs))
                {
                    reader.BaseStream.Seek(beginPosition, SeekOrigin.Begin);
                    byte[] content = reader.ReadBytes((int)(endPosition - beginPosition));

                    using (FileStream output = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
                    {
                        output.Write(content, 0, content.Length);
                    }
                }
            }
        }
    }

}