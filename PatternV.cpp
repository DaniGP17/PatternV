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
#include <cstring>

bool useColors = true;

#define RED     (useColors ? "\033[31m" : "")
#define GREEN   (useColors ? "\033[32m" : "")
#define YELLOW  (useColors ? "\033[33m" : "")
#define RESET   (useColors ? "\033[0m" : "")

namespace fs = std::filesystem;

constexpr auto TARGET_EXTENSION_EXE = ".exe";
constexpr auto TARGET_EXTENSION_TEXT = ".text";

struct ResultLine {
    int build;
    std::string line;
};

struct SectionInfo {
    size_t rawOffset;
    size_t rawSize;
};

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

std::string extractGameName(const std::string& filename) {
    std::string nameOnly = filename.substr(0, filename.find_last_of('.'));

    size_t dashPos = nameOnly.find('-');
    size_t underscorePos = nameOnly.find('_');

    size_t sepPos = std::min(
        dashPos == std::string::npos ? nameOnly.size() : dashPos,
        underscorePos == std::string::npos ? nameOnly.size() : underscorePos
    );

    if (sepPos == std::string::npos) return nameOnly;

    return nameOnly.substr(0, sepPos);
}

std::optional<std::string> extractBuildNumber(const std::string& filename) {
    std::regex pattern(R"((\d{4}))");
    std::smatch match;

    if (std::regex_search(filename, match, pattern)) {
        return match[1];
    }

    return std::nullopt;
}

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

void scanFile(const fs::path& filePath, const std::vector<std::optional<uint8_t>>& pattern,
              std::mutex& outputMutex, std::vector<ResultLine>& outputBuffer)
{
    const auto filename = filePath.filename().string();
    const auto buffer = readFile(filePath);
    if (buffer.empty()) return;

    const uint8_t* textSegment = nullptr;
    size_t textSize = 0;

    if (filePath.extension() == TARGET_EXTENSION_TEXT) {
        textSegment = buffer.data();
        textSize = buffer.size();
    } else {
        auto textSection = getTextSection(buffer);
        if (!textSection.has_value()) {
            std::lock_guard lock(outputMutex);
            std::cerr << RED << "[-] .text section not found in: " << filename << RESET << '\n';
            return;
        }
        textSegment = buffer.data() + textSection->rawOffset;
        textSize = textSection->rawSize;
    }

    const auto gameName = extractGameName(filename);
    const auto build = extractBuildNumber(filename).value_or(filename);
    const auto matches = searchAllPatternOffsets(textSegment, textSize, pattern);

    std::ostringstream oss;
    if (!matches.empty()) {
        oss << GREEN << "[+]" << RESET << " Pattern found in " << gameName << " v" << YELLOW << build
            << RESET << " (" << matches.size() << " matches): ";
        for (size_t i = 0; i < matches.size(); ++i) {
            oss << YELLOW << "0x" << std::hex << std::uppercase << matches[i] << RESET;
            if (i != matches.size() - 1)
                oss << ", ";
        }
    } else {
        oss << RED << "[-]" << RESET << " Pattern not found in " << gameName << " v" << YELLOW << build << RESET;
    }

    {
        std::lock_guard lock(outputMutex);
        try {
            int buildNum = std::stoi(build);
            outputBuffer.push_back({ buildNum, oss.str() });
        } catch (...) {
            outputBuffer.push_back({ 0, oss.str() });
        }
    }
}

void scanFileLimited(const fs::path& filePath, const std::vector<std::optional<uint8_t>>& pattern, std::mutex& outputMutex, std::vector<ResultLine>& outputBuffer)
{
    sem.acquire();
    scanFile(filePath, pattern, outputMutex, outputBuffer);
    sem.release();
}

bool scanDirectory(const fs::path& folderPath, const std::vector<std::optional<uint8_t>>& pattern) {
    using namespace std::chrono;
    const auto start = high_resolution_clock::now();

    std::vector<ResultLine> outputBuffer;
    std::mutex outputMutex;
    std::vector<std::future<void>> futures;

    std::vector<fs::path> buildFiles;
    for (const auto& entry : fs::directory_iterator(folderPath)) {
        if (entry.is_regular_file()) {
            auto ext = entry.path().extension().string();
            if (ext == TARGET_EXTENSION_EXE || ext == TARGET_EXTENSION_TEXT) {
                buildFiles.push_back(entry.path());
            }
        }
    }

    for (const auto& path : buildFiles) {
        futures.push_back(std::async(std::launch::async, scanFileLimited,
                                     path, std::cref(pattern),
                                     std::ref(outputMutex), std::ref(outputBuffer)));
    }

    for (auto& f : futures) f.get();

    bool allFound = true;
    {
        std::lock_guard lock(outputMutex);
        std::sort(outputBuffer.begin(), outputBuffer.end(),
                  [](const ResultLine& a, const ResultLine& b) {
                      return a.build < b.build;
                  });

        for (const auto& result : outputBuffer) {
            std::cout << result.line << '\n';
            if (result.line.find("Pattern not found") != std::string::npos) {
                allFound = false;
            }
        }
    }

    const auto end = high_resolution_clock::now();
    std::cout << "\n[~] Scan completed in "
              << duration_cast<milliseconds>(end - start).count()
              << " ms\n";

    return allFound;
}

void extractTextSections(const fs::path& folderPath) {
    for (const auto& entry : fs::directory_iterator(folderPath)) {
        if (!entry.is_regular_file() || entry.path().extension() != TARGET_EXTENSION_EXE)
            continue;

        const auto buffer = readFile(entry.path());
        if (buffer.empty())
            continue;

        auto textSection = getTextSection(buffer);
        if (!textSection.has_value()) {
            std::cerr << RED << "[-] .text section not found in: " 
                      << entry.path().filename().string() << RESET << '\n';
            continue;
        }

        fs::path outPath = entry.path();
        outPath += ".text";

        std::ofstream outFile(outPath, std::ios::binary);
        if (!outFile) {
            std::cerr << RED << "[-] Failed to create: " << outPath << RESET << '\n';
            continue;
        }

        outFile.write(
            reinterpret_cast<const char*>(buffer.data() + textSection->rawOffset),
            textSection->rawSize
        );

        std::cout << GREEN << "[+]" << RESET << " Extracted .text from " 
                  << entry.path().filename().string()
                  << " -> " << outPath.filename().string()
                  << " (" << textSection->rawSize << " bytes)\n";
    }
}

int main(int argc, char* argv[])
{
    fs::path folderPath = "Builds/";
    std::string argPattern;

    bool extractMode = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--no-color") {
            useColors = false;
        } else if (arg == "--extract-text") {
            extractMode = true;
        } else if (folderPath == "Builds/") {
            folderPath = arg; 
        } else if (argPattern.empty()) {
            argPattern = arg;
        }
    }

    if (extractMode) {
        extractTextSections(folderPath);
        return 0;
    }

    if (!argPattern.empty())
    {
        auto pattern = parseBytePattern(argPattern);

        if (pattern.empty())
        {
            std::cerr << "Invalid pattern provided as argument.\n";
            return 1;
        }

        bool ok = scanDirectory(folderPath, pattern);
        return ok ? 0 : 2;
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
            break;
        }

        scanDirectory(folderPath, pattern);
        std::cout << "\n";
    }
    
    return 0;
}