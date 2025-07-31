#include <iostream>
#include <filesystem>
#include <string>
#include <fstream>
#include <regex>
#include <chrono>
#include <thread>
#include <mutex>
#include <vector>
#include <future>
#include <semaphore>

#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define RESET   "\033[0m"

namespace fs = std::filesystem;

constexpr auto TARGET_EXTENSION = ".exe";

std::counting_semaphore<> sem(std::thread::hardware_concurrency());

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

std::vector<size_t> searchAllPatternOffsets(const uint8_t* data, size_t size, const std::vector<std::optional<uint8_t>>& pattern) {
    std::vector<size_t> matches;
    if (size < pattern.size()) return matches;

    for (size_t i = 0; i <= size - pattern.size(); ++i) {
        bool matched = true;
        for (size_t j = 0; j < pattern.size(); ++j) {
            if (pattern[j].has_value() && data[i + j] != pattern[j].value()) {
                matched = false;
                break;
            }
        }
        if (matched) matches.push_back(i);
    }

    return matches;
}

std::vector<uint8_t> readFile(const fs::path& filepath) {
    FILE* file = nullptr;

#ifdef _WIN32
    if (fopen_s(&file, filepath.string().c_str(), "rb") != 0 || !file) {
        std::cerr << "Failed to open: " << filepath << '\n';
        return {};
    }
#else
    file = fopen(filepath.string().c_str(), "rb");
    if (!file) {
        std::cerr << "Failed to open: " << filepath << '\n';
        return {};
    }
#endif

    if (std::fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        std::cerr << "fseek() failed on: " << filepath << '\n';
        return {};
    }
    
    long size = std::ftell(file);
    if (size <= 0) {
        fclose(file);
        std::cerr << "Empty or invalid file: " << filepath << '\n';
        return {};
    }
    rewind(file);

    std::vector<uint8_t> buffer(size);
    if (std::fread(buffer.data(), 1, size, file) != static_cast<size_t>(size)) {
        fclose(file);
        std::cerr << "Failed to read: " << filepath << '\n';
        return {};
    }

    fclose(file);
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

void scanFile(const fs::path& filePath, const std::vector<std::optional<uint8_t>>& pattern, std::mutex& outputMutex, std::vector<std::string>& outputBuffer)
{
    const auto filename = filePath.filename().string();
    const auto buffer = readFile(filePath);
    if (buffer.empty()) return;

    auto textSection = getTextSection(buffer);
    if (!textSection.has_value()) {
        std::lock_guard lock(outputMutex);
        std::cerr << RED << "[-] .text section not found in: " << filename << RESET << '\n';
        return;
    }

    const uint8_t* textSegment = buffer.data() + textSection->rawOffset;
    size_t textSize = textSection->rawSize;

    const auto build = extractBuildNumber(filename).value_or(filename);
    const auto matches = searchAllPatternOffsets(textSegment, textSize, pattern);

    std::ostringstream oss;
    if (!matches.empty()) {
        oss << GREEN << "[+]" << RESET << " Pattern found in v" << YELLOW << build << RESET << " (" << matches.size() << " matches): ";
        for (size_t i = 0; i < matches.size(); ++i) {
            oss << YELLOW << "0x" << std::hex << std::uppercase << matches[i] << RESET;
            if (i != matches.size() - 1)
                oss << ", ";
        }
        oss << RESET << std::dec;
    } else {
        oss << RED << "[-]" << RESET << " Pattern not found in v" << YELLOW << build << RESET;
    }

    {
        std::lock_guard lock(outputMutex);
        outputBuffer.push_back(oss.str());
    }
}

void scanFileLimited(const fs::path& filePath, const std::vector<std::optional<uint8_t>>& pattern, std::mutex& outputMutex, std::vector<std::string>& outputBuffer)
{
    sem.acquire();
    scanFile(filePath, pattern, outputMutex, outputBuffer);
    sem.release();
}

void scanDirectory(const fs::path& folderPath, const std::vector<std::optional<uint8_t>>& pattern) {
    using namespace std::chrono;
    const auto start = high_resolution_clock::now();

    std::vector<std::string> outputBuffer;
    std::mutex outputMutex;
    std::vector<std::future<void>> futures;
    
    std::vector<fs::path> buildFiles;
    for (const auto& entry : fs::directory_iterator(folderPath)) {
        if (entry.is_regular_file() && entry.path().extension() == TARGET_EXTENSION) {
            buildFiles.push_back(entry.path());
        }
    }

    for (const auto& path : buildFiles) {
        futures.push_back(std::async(std::launch::async, scanFileLimited, path, std::cref(pattern), std::ref(outputMutex), std::ref(outputBuffer)));
    }

    for (auto& f : futures) {
        f.get();
    }
    
    {
        std::lock_guard lock(outputMutex);
        for (const auto& line : outputBuffer) {
            std::cout << line << '\n';
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