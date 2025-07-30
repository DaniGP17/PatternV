#include <iostream>
#include <filesystem>
#include <string>
#include <fstream>
#include <regex>

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

void scanDirectory(const fs::path& folderPath, const std::vector<std::optional<uint8_t>>& pattern) {
    for (const auto& entry : fs::directory_iterator(folderPath)) {
        if (!entry.is_regular_file() || entry.path().extension() != TARGET_EXTENSION)
            continue;

        const auto& filePath = entry.path();
        const auto filename = filePath.filename().string();

        const auto buffer = readFile(filePath);
        if (buffer.empty()) continue;

        const auto build = extractBuildNumber(filename).value_or(filename);
        const auto matches = searchAllPatternOffsets(buffer, pattern);

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
}

int main(int argc, char* argv[])
{
    fs::path folderPath = "Builds/";

    if(argc > 1)
    {
        folderPath = argv[1];
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