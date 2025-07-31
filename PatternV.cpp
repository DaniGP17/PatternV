#include <iostream>
#include <filesystem>
#include <string>
#include <fstream>
#include <regex>
#include <chrono>

namespace fs = std::filesystem;

constexpr auto TARGET_EXTENSION = ".exe";

std::vector<std::optional<uint8_t>> parseBytePattern(const std::string& input)
{
    std::vector<std::optional<uint8_t>> pattern;
    std::istringstream stream(input);
    std::string byteStr;

    while(stream >> byteStr)
    {
        if (byteStr == "?" || byteStr == "??")
        {
            pattern.push_back(std::nullopt);
        }
        else
        {
            try
            {
                uint8_t byte = static_cast<uint8_t>(std::stoul(byteStr, nullptr, 16));
                pattern.push_back(byte);
            }
            catch (...)
            {
                std::cerr << "Invalid byte: " << byteStr << "\n";
            }
        }
    }
    
    return pattern;
}

bool matchesAt(const std::vector<uint8_t>& buffer, size_t pos, const std::vector<std::optional<uint8_t>>& pattern) {
    if (pos + pattern.size() > buffer.size()) return false;

    for (size_t i = 0; i < pattern.size(); ++i) {
        if (pattern[i].has_value() && buffer[pos + i] != pattern[i].value()) {
            return false;
        }
    }

    return true;
}

std::vector<size_t> searchAllPatternOffsets(const std::vector<uint8_t>& buffer, const std::vector<std::optional<uint8_t>>& pattern) {
    std::vector<size_t> matches;
    if (buffer.size() < pattern.size()) return matches;

    for (size_t i = 0; i <= buffer.size() - pattern.size(); ++i) {
        if (matchesAt(buffer, i, pattern)) {
            matches.push_back(i);
        }
    }

    return matches;
}

std::vector<uint8_t> readFile(const fs::path& filepath) {
    std::ifstream file(filepath, std::ios::binary | std::ios::ate);
    if (!file) {
        std::cerr << "Failed to open: " << filepath << '\n';
        return {};
    }

    std::streamsize size = file.tellg();
    file.seekg(0);

    std::vector<uint8_t> buffer(size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        std::cerr << "Failed to read: " << filepath << '\n';
        return {};
    }

    return buffer;
}

std::optional<std::string> extractBuildNumber(const std::string& filename) {
    std::regex pattern(R"((\d{4}))");
    std::smatch match;

    if (std::regex_search(filename, match, pattern)) {
        return match[1];
    }

    return std::nullopt;
}

struct SectionInfo {
    size_t rawOffset;
    size_t rawSize;
};

std::optional<SectionInfo> getTextSection(const std::vector<uint8_t>& buffer) {
    if (buffer.size() < 0x1000) return std::nullopt;

    const uint32_t dosSignature = *reinterpret_cast<const uint16_t*>(&buffer[0x00]);
    if (dosSignature != 0x5A4D) return std::nullopt; // MZ

    const uint32_t peOffset = *reinterpret_cast<const uint32_t*>(&buffer[0x3C]);
    if (peOffset + 0x18 >= buffer.size()) return std::nullopt;

    const uint32_t peSignature = *reinterpret_cast<const uint32_t*>(&buffer[peOffset]);
    if (peSignature != 0x00004550) return std::nullopt; // PE\0\0

    const uint16_t numberOfSections = *reinterpret_cast<const uint16_t*>(&buffer[peOffset + 6]);
    const uint16_t sizeOfOptionalHeader = *reinterpret_cast<const uint16_t*>(&buffer[peOffset + 20]);

    size_t sectionTableOffset = peOffset + 24 + sizeOfOptionalHeader;
    for (int i = 0; i < numberOfSections; ++i) {
        if (sectionTableOffset + 40 > buffer.size()) break;

        const char* name = reinterpret_cast<const char*>(&buffer[sectionTableOffset]);
        if (std::strncmp(name, ".text", 5) == 0) {
            const uint32_t rawDataPtr = *reinterpret_cast<const uint32_t*>(&buffer[sectionTableOffset + 20]);
            const uint32_t rawSize = *reinterpret_cast<const uint32_t*>(&buffer[sectionTableOffset + 16]);
            if (rawDataPtr + rawSize <= buffer.size()) {
                return SectionInfo{ rawDataPtr, rawSize };
            }
        }

        sectionTableOffset += 40;
    }

    return std::nullopt;
}

void scanDirectory(const fs::path& folderPath, const std::vector<std::optional<uint8_t>>& pattern) {
    using namespace std::chrono;
    const auto start = high_resolution_clock::now();
    
    for (const auto& entry : fs::directory_iterator(folderPath)) {
        if (!entry.is_regular_file() || entry.path().extension() != TARGET_EXTENSION)
            continue;

        const auto& filePath = entry.path();
        const auto filename = filePath.filename().string();

        const auto buffer = readFile(filePath);
        if (buffer.empty()) continue;

        auto textSection = getTextSection(buffer);
        if (!textSection.has_value()) {
            std::cerr << "[-] .text section not found in: " << filename << '\n';
            continue;
        }

        std::vector<uint8_t> textSegment(buffer.begin() + textSection->rawOffset,
                                         buffer.begin() + textSection->rawOffset + textSection->rawSize);

        const auto build = extractBuildNumber(filename).value_or(filename);
        const auto matches = searchAllPatternOffsets(textSegment, pattern);

        if (!matches.empty()) {
            std::cout << "[+] Pattern found in v" << build << " (" << matches.size() << " matches): ";
            for (size_t i = 0; i < matches.size(); ++i) {
                std::cout << "0x" << std::hex << std::uppercase << matches[i];
                if (i != matches.size() - 1)
                    std::cout << ", ";
            }
            std::cout << std::dec << '\n';
        } else {
            std::cout << "[-] Pattern not found in v" << build << '\n';
        }
    }

    const auto end = high_resolution_clock::now();
    const auto duration = duration_cast<milliseconds>(end - start).count();
    std::cout << "\n[~] Scan completed in " << duration << " ms\n";
}

int main(int argc, char* argv[])
{
    fs::path folderPath = "Builds/";
    std::string argPattern;

    if(argc > 1)
    {
        folderPath = argv[1];
        if (argc > 2)
        {
            argPattern = argv[2];
        }
    }

    if (!argPattern.empty())
    {
        auto pattern = parseBytePattern(argPattern);

        if (pattern.empty())
        {
            std::cerr << "Invalid pattern provided as argument.\n";
            return 1;
        }

        scanDirectory(folderPath, pattern);
        return 0;
    }

    if (!fs::exists(folderPath) || !fs::is_directory(folderPath)) {
        std::cerr << "Can't find the builds path at: " << folderPath << ".\n";
        return 1;
    }

    while(true)
    {
        std::cout << "> ";
        std::string input;
        std::getline(std::cin, input);

        auto pattern = parseBytePattern(input);

        if(pattern.empty())
        {
            std::cout << "Invalid pattern.\n";
            continue;
        }

        scanDirectory(folderPath, pattern);
        std::cout << "\n";
    }
    
    return 0;
}