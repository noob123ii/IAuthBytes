using System;
using System.Collections.Generic;
using System.Text;

namespace IAuthBytes
{
    internal static class PeAnalyzer
    {
        public struct PeSection
        {
            public string Name;
            public int VirtualSize;
            public int RawSize;
            public int VirtualAddress;
            public int RawAddress;
            public double Entropy;
        }

        public struct PeInfo
        {
            public bool IsValid;
            public bool Is64Bit;
            public bool IsManaged;
            public short NumberOfSections;
            public List<PeSection> Sections;
            public List<string> ImportedFunctions;
            public List<string> ImportedDlls;
            public long OverlayOffset;
            public int OverlaySize;
            public double EntryPointEntropy;
            public bool HasResourceSection;
            public int ResourceSize;
        }

        public static PeInfo Analyze(byte[] fileBytes)
        {
            var info = new PeInfo { Sections = new List<PeSection>(), ImportedFunctions = new List<string>(), ImportedDlls = new List<string>() };

            if (fileBytes.Length < 64) return info;
            if (fileBytes[0] != 0x4D || fileBytes[1] != 0x5A) return info;

            int peOffset = BitConverter.ToInt32(fileBytes, 0x3C);
            if (peOffset < 0 || peOffset + 4 >= fileBytes.Length) return info;
            if (fileBytes[peOffset] != 0x50 || fileBytes[peOffset + 1] != 0x45) return info;

            info.IsValid = true;

            int optionalHeaderOffset = peOffset + 24;
            short magic = BitConverter.ToInt16(fileBytes, optionalHeaderOffset);
            info.Is64Bit = magic == 0x20B;

            info.NumberOfSections = BitConverter.ToInt16(fileBytes, peOffset + 6);
            short sizeOfOptionalHeader = BitConverter.ToInt16(fileBytes, peOffset + 20);

            int sectionTableOffset = peOffset + 24 + sizeOfOptionalHeader;

            if (sizeOfOptionalHeader >= 208)
            {
                int clrHeaderRva = BitConverter.ToInt32(fileBytes, optionalHeaderOffset + 208);
                if (clrHeaderRva > 0)
                    info.IsManaged = true;
            }

            int maxEndOfRaw = 0;
            for (int i = 0; i < Math.Min((int)info.NumberOfSections, 96); i++)
            {
                int offset = sectionTableOffset + (i * 40);
                if (offset + 40 > fileBytes.Length) break;

                var section = new PeSection
                {
                    Name = Encoding.ASCII.GetString(fileBytes, offset, 8).TrimEnd('\0'),
                    VirtualSize = BitConverter.ToInt32(fileBytes, offset + 8),
                    VirtualAddress = BitConverter.ToInt32(fileBytes, offset + 12),
                    RawSize = BitConverter.ToInt32(fileBytes, offset + 16),
                    RawAddress = BitConverter.ToInt32(fileBytes, offset + 20),
                };

                if (section.RawAddress > 0 && section.RawSize > 0 &&
                    section.RawAddress + section.RawSize <= fileBytes.Length)
                {
                    byte[] sectionData = new byte[section.RawSize];
                    Array.Copy(fileBytes, section.RawAddress, sectionData, 0, section.RawSize);
                    section.Entropy = CalcEntropy(sectionData);
                }

                int sectionEnd = section.RawAddress + section.RawSize;
                if (sectionEnd > maxEndOfRaw)
                    maxEndOfRaw = sectionEnd;

                if (section.Name == ".rsrc")
                {
                    info.HasResourceSection = true;
                    info.ResourceSize = section.RawSize;
                }

                info.Sections.Add(section);
            }

            if (maxEndOfRaw > 0 && maxEndOfRaw < fileBytes.Length)
            {
                info.OverlayOffset = maxEndOfRaw;
                info.OverlaySize = fileBytes.Length - maxEndOfRaw;
            }

            try
            {
                int entryPoint = BitConverter.ToInt32(fileBytes, optionalHeaderOffset + 16);
                if (entryPoint > 0 && entryPoint < fileBytes.Length)
                {
                    int epRegionSize = Math.Min(512, fileBytes.Length - entryPoint);
                    byte[] epRegion = new byte[epRegionSize];
                    Array.Copy(fileBytes, entryPoint, epRegion, 0, epRegionSize);
                    info.EntryPointEntropy = CalcEntropy(epRegion);
                }
            }
            catch { }

            try
            {
                int importDirRva = 0;
                int importDirSize = 0;
                if (info.Is64Bit)
                {
                    importDirRva = BitConverter.ToInt32(fileBytes, optionalHeaderOffset + 120);
                    importDirSize = BitConverter.ToInt32(fileBytes, optionalHeaderOffset + 124);
                }
                else
                {
                    importDirRva = BitConverter.ToInt32(fileBytes, optionalHeaderOffset + 104);
                    importDirSize = BitConverter.ToInt32(fileBytes, optionalHeaderOffset + 108);
                }

                if (importDirRva > 0 && importDirSize > 0)
                {
                    int importTableOffset = RvaToOffset(fileBytes, peOffset, optionalHeaderOffset, importDirRva, info.Is64Bit);
                    if (importTableOffset > 0)
                    {
                        for (int i = 0; i < 256; i++)
                        {
                            int entryOffset = importTableOffset + (i * 20);
                            if (entryOffset + 20 > fileBytes.Length) break;

                            int nameRva = BitConverter.ToInt32(fileBytes, entryOffset + 12);
                            if (nameRva == 0) break;

                            int nameOffset = RvaToOffset(fileBytes, peOffset, optionalHeaderOffset, nameRva, info.Is64Bit);
                            if (nameOffset > 0 && nameOffset < fileBytes.Length)
                            {
                                string dllName = ReadAsciiString(fileBytes, nameOffset);
                                if (!string.IsNullOrEmpty(dllName))
                                    info.ImportedDlls.Add(dllName);
                            }
                        }
                    }
                }
            }
            catch { }

            return info;
        }

        private static int RvaToOffset(byte[] fileBytes, int peOffset, int optionalHeaderOffset, int rva, bool is64Bit)
        {
            short numberOfSections = BitConverter.ToInt16(fileBytes, peOffset + 6);
            short sizeOfOptionalHeader = BitConverter.ToInt16(fileBytes, peOffset + 20);
            int sectionTableOffset = peOffset + 24 + sizeOfOptionalHeader;

            for (int i = 0; i < Math.Min((int)numberOfSections, 96); i++)
            {
                int offset = sectionTableOffset + (i * 40);
                if (offset + 40 > fileBytes.Length) break;

                int sectionVA = BitConverter.ToInt32(fileBytes, offset + 12);
                int sectionRawSize = BitConverter.ToInt32(fileBytes, offset + 16);
                int sectionRawAddr = BitConverter.ToInt32(fileBytes, offset + 20);
                int sectionVirtualSize = BitConverter.ToInt32(fileBytes, offset + 8);

                if (rva >= sectionVA && rva < sectionVA + Math.Max(sectionVirtualSize, sectionRawSize))
                {
                    return sectionRawAddr + (rva - sectionVA);
                }
            }
            return 0;
        }

        private static string ReadAsciiString(byte[] data, int offset)
        {
            var sb = new StringBuilder();
            for (int i = offset; i < data.Length && i < offset + 256; i++)
            {
                if (data[i] == 0) break;
                sb.Append((char)data[i]);
            }
            return sb.ToString();
        }

        public static double CalcEntropy(byte[] data)
        {
            if (data.Length == 0) return 0;
            int[] counts = new int[256];
            foreach (byte b in data) counts[b]++;
            double entropy = 0, len = data.Length;
            foreach (int c in counts)
                if (c > 0) { double p = c / len; entropy -= p * Math.Log(p, 2); }
            return entropy;
        }
    }
}
