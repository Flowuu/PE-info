#include "../include/flogger.hpp"
#include <filesystem>

struct PEHeaders {
    PIMAGE_DOS_HEADER dosHdr;
    PIMAGE_NT_HEADERS ntHdr;
    PIMAGE_FILE_HEADER fileHdr;
    PIMAGE_OPTIONAL_HEADER optionalHdr;
    PIMAGE_SECTION_HEADER sectionHdr;
};

struct inFile {
    std::filesystem::path filePath;
    uint8_t* fileBuffer;
    size_t fileSize;

    PEHeaders header;
};

// https://en.wikipedia.org/wiki/Unix_time
tm unixTime(DWORD dwTime) {
    time_t rawTime = static_cast<time_t>(dwTime);
    tm timeInfo;

    localtime_s(&timeInfo, &rawTime);

    return timeInfo;
}

#ifdef _WIN64
uintptr_t rvaToFileOffset(uintptr_t RVA, PIMAGE_NT_HEADERS& pNtHeader) {
    if (!pNtHeader) return 0;

    PIMAGE_FILE_HEADER fileHdr       = &pNtHeader->FileHeader;
    PIMAGE_SECTION_HEADER sectionHdr = IMAGE_FIRST_SECTION(pNtHeader);

    for (int i = 0; i < fileHdr->NumberOfSections; i++) {
        DWORD sectionVA   = sectionHdr[i].VirtualAddress;
        DWORD sectionSize = sectionHdr[i].SizeOfRawData;

        if (RVA >= sectionVA && RVA < sectionVA + sectionSize) return RVA - sectionVA + sectionHdr[i].PointerToRawData;
    }

    return 0;
}
#else
DWORD rvaToFileOffset(DWORD RVA, PIMAGE_NT_HEADERS& pNtHeader) {
    if (!pNtHeader) return 0;

    PIMAGE_FILE_HEADER fileHdr       = &pNtHeader->FileHeader;
    PIMAGE_SECTION_HEADER sectionHdr = IMAGE_FIRST_SECTION(pNtHeader);

    for (int i = 0; i < fileHdr->NumberOfSections; i++) {
        DWORD sectionVA   = sectionHdr[i].VirtualAddress;
        DWORD sectionSize = sectionHdr[i].SizeOfRawData;

        if (RVA >= sectionVA && RVA < sectionVA + sectionSize) return RVA - sectionVA + sectionHdr[i].PointerToRawData;
    }

    return 0;
}
#endif  // _WIN64

void readReloc(PEHeaders& header) {
    PIMAGE_BASE_RELOCATION relocDir;
#ifdef _WIN64
    relocDir = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
        reinterpret_cast<uintptr_t>(header.dosHdr) +
        rvaToFileOffset(header.optionalHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress, header.ntHdr));
#else
    relocDir = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
        reinterpret_cast<DWORD>(header.dosHdr) +
        rvaToFileOffset(header.optionalHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress, header.ntHdr));
#endif  // _WIN64

    console->log(LogLevel::lightcyan, "[Relocation Directory Table]\n");

    for (int tableEntryCount = 0; relocDir->VirtualAddress != 0 && relocDir->SizeOfBlock != 0; tableEntryCount++) {
        int numberOfEntry = static_cast<int>((relocDir->SizeOfBlock - sizeof(PIMAGE_BASE_RELOCATION)) / sizeof(WORD));
        console->log("%d entry -> 0x%X (entry count %d)\n", tableEntryCount, relocDir->VirtualAddress, numberOfEntry);

        for (int relocationEntryCount = 0; relocationEntryCount < numberOfEntry; relocationEntryCount++) {
            PWORD relocationEntry = reinterpret_cast<PWORD>(relocDir + 0x1);

            console->log("  %d entry -> 0x%X\n", relocationEntryCount, relocationEntry[relocationEntryCount]);
        }
        console->log("\n");

#ifdef _WIN64
        relocDir = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<uintptr_t>(relocDir) + relocDir->SizeOfBlock);
#else
        relocDir = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<DWORD>(relocDir) + relocDir->SizeOfBlock);
#endif  // _WIN64
    }
}

void readImports(PEHeaders& header) {
    PIMAGE_IMPORT_DESCRIPTOR importDesc;
#ifdef _WIN64
    importDesc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
        reinterpret_cast<uintptr_t>(header.dosHdr) +
        rvaToFileOffset(header.optionalHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, header.ntHdr));
#else
    importDesc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
        reinterpret_cast<DWORD>(header.dosHdr) + rvaToFileOffset(header.optionalHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, header.ntHdr));
#endif  // _WIN64

    console->log(LogLevel::lightcyan, "[Import Directory Table]\n");
    for (; importDesc->Name != 0; importDesc++) {
        const char* moduleName;
        PIMAGE_THUNK_DATA oThunkData;
#ifdef _WIN64
        moduleName = reinterpret_cast<const char*>(reinterpret_cast<uintptr_t>(header.dosHdr) + rvaToFileOffset(importDesc->Name, header.ntHdr));
        oThunkData =
            reinterpret_cast<PIMAGE_THUNK_DATA>(reinterpret_cast<uintptr_t>(header.dosHdr) + rvaToFileOffset(importDesc->OriginalFirstThunk, header.ntHdr));
#else
        moduleName = reinterpret_cast<const char*>(reinterpret_cast<DWORD>(header.dosHdr) + rvaToFileOffset(importDesc->Name, header.ntHdr));
        oThunkData =
            reinterpret_cast<PIMAGE_THUNK_DATA>(reinterpret_cast<DWORD>(header.dosHdr) + rvaToFileOffset(importDesc->OriginalFirstThunk, header.ntHdr));
#endif  // _WIN64

        console->log(LogLevel::orange, "  %s:\n", moduleName);

        for (; oThunkData->u1.AddressOfData != 0; oThunkData++) {
            if (IMAGE_SNAP_BY_ORDINAL(oThunkData->u1.Ordinal)) {
                console->log("    %u\n", IMAGE_ORDINAL(rvaToFileOffset(oThunkData->u1.Ordinal, header.ntHdr)));

            } else {
                PIMAGE_IMPORT_BY_NAME functionName;
#ifdef _WIN64
                functionName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(reinterpret_cast<uintptr_t>(header.dosHdr) +
                                                                       rvaToFileOffset(oThunkData->u1.Function, header.ntHdr));
#else
                functionName =
                    reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(reinterpret_cast<DWORD>(header.dosHdr) + rvaToFileOffset(oThunkData->u1.Function, header.ntHdr));
#endif  // _WIN64
                console->log("    %s\n", functionName->Name);
            }
        }
        console->log("\n");
    }
    console->log("\n");
}

void readHeaders(inFile& inputFile) {
    inputFile.header.dosHdr      = reinterpret_cast<PIMAGE_DOS_HEADER>(inputFile.fileBuffer);
    inputFile.header.ntHdr       = reinterpret_cast<PIMAGE_NT_HEADERS>(inputFile.fileBuffer + inputFile.header.dosHdr->e_lfanew);
    inputFile.header.fileHdr     = &inputFile.header.ntHdr->FileHeader;
    inputFile.header.optionalHdr = &inputFile.header.ntHdr->OptionalHeader;
    inputFile.header.sectionHdr  = IMAGE_FIRST_SECTION(inputFile.header.ntHdr);

    if (inputFile.header.dosHdr->e_magic != IMAGE_DOS_SIGNATURE || inputFile.header.ntHdr->Signature != IMAGE_NT_SIGNATURE) {
        console->report(LogLevel::error, "cant get headers info\n");
        return;
    }

#ifdef _WIN64
    if (inputFile.header.fileHdr->Machine != IMAGE_FILE_MACHINE_AMD64) {
        console->report(LogLevel::error, "architecture mismatch\n");
        return;
    }
#else
    if (inputFile.header.fileHdr->Machine != IMAGE_FILE_MACHINE_I386) {
        console->report(LogLevel::error, "architecture mismatch\n");
        return;
    }
#endif  // _WIN64

    console->log(LogLevel::green, "[DOS info] -> 0x%X\n", inputFile.header.dosHdr);
    console->log("e_magic:  %X\n", inputFile.header.dosHdr->e_magic);
    console->log("e_lfanew: %X\n\n", inputFile.header.dosHdr->e_lfanew);

    console->log(LogLevel::green, "[NT info] -> 0x%X\n", inputFile.header.ntHdr);
    console->log("Signature:      %X\n", inputFile.header.ntHdr->Signature);
    console->log("FileHeader:     %X\n", inputFile.header.ntHdr->FileHeader);
    console->log("OptionalHeader: %X\n\n", inputFile.header.ntHdr->OptionalHeader);

    tm timeStamp = unixTime(inputFile.header.fileHdr->TimeDateStamp);
    console->log(LogLevel::green, "[file info] -> 0x%X\n", inputFile.header.fileHdr);
    console->log("Machine: %X (%s)\n", inputFile.header.fileHdr->Machine, inputFile.header.fileHdr->Machine == IMAGE_FILE_MACHINE_AMD64 ? "64-bit" : "32-bit");
    console->log("section num: %d\n", static_cast<int>(inputFile.header.fileHdr->NumberOfSections));
    console->log("timestamp:\n");
    console->log("  year---%d\n", static_cast<int>(timeStamp.tm_year + 1900));
    console->log("  month--%d\n", static_cast<int>(timeStamp.tm_mon + 1));
    console->log("  day----%d\n", static_cast<int>(timeStamp.tm_mday));
    console->log("  hour---%d\n", static_cast<int>(timeStamp.tm_hour));
    console->log("size of optional hdr: %X\n\n", inputFile.header.fileHdr->SizeOfOptionalHeader);

    console->log(LogLevel::green, "[optional info] -> 0x%X\n", inputFile.header.optionalHdr);
    console->log("entry: 0x%X\n", inputFile.header.optionalHdr->AddressOfEntryPoint);
    console->log("BaseOfCode:  0x%X\n", inputFile.header.optionalHdr->BaseOfCode);
    console->log("SizeOfCode:  %X\n", inputFile.header.optionalHdr->SizeOfCode);
    console->log("ImageBase:   0x%X\n", inputFile.header.optionalHdr->ImageBase);
    console->log("SizeOfImage: %X\n", inputFile.header.optionalHdr->SizeOfImage);
    console->log("FileAlignment:    %X\n", inputFile.header.optionalHdr->FileAlignment);
    console->log("SectionAlignment: %X\n", inputFile.header.optionalHdr->SectionAlignment);
    console->log("SizeOfHeaders:    %X\n\n", inputFile.header.optionalHdr->SizeOfHeaders);

    console->log(LogLevel::green, "[sections] -> %d\n", static_cast<int>(inputFile.header.fileHdr->NumberOfSections));
    for (WORD i = 0; i < inputFile.header.fileHdr->NumberOfSections; i++)
        console->log("%s -> 0x%X\n", inputFile.header.sectionHdr[i].Name, inputFile.header.sectionHdr[i].Name);

    console->log("\n");

    readImports(inputFile.header);
    readReloc(inputFile.header);
}

int main(int argc, char** argv) {
    inFile inputFile;

    console->log(LogLevel::orange, "[PE info]\n");

    if (argc == 1) {
        inputFile.filePath = console->getInput<std::string>("file -> ");
    } else {
        inputFile.filePath = argv[1];
    }

    HANDLE hFile = CreateFileA(inputFile.filePath.string().c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        console->report(LogLevel::error, "%s\n", console->getLastError().c_str());
        return 1;
    }

    inputFile.fileSize = GetFileSize(hFile, nullptr);
    if (!inputFile.fileSize) {
        console->report(LogLevel::error, "%s\n", console->getLastError().c_str());
        CloseHandle(hFile);
        return 1;
    }

    inputFile.fileBuffer = static_cast<uint8_t*>(malloc(inputFile.fileSize));

    if (!ReadFile(hFile, inputFile.fileBuffer, static_cast<DWORD>(inputFile.fileSize), nullptr, nullptr)) {
        console->report(LogLevel::error, "%s\n", console->getLastError().c_str());
        CloseHandle(hFile);
        free(inputFile.fileBuffer);
        return 1;
    }

    CloseHandle(hFile);

    console->clear();
    console->log(LogLevel::lightcyan, "[file info]\n");
    console->log("file name: %s\n", inputFile.filePath.filename().string().c_str());
    console->log("file size: %d KB\n", static_cast<int>(inputFile.fileSize / 1000));
    console->log("file type: %s\n\n", inputFile.filePath.extension().string().c_str());

    readHeaders(inputFile);

    free(inputFile.fileBuffer);

    system("pause");
    return 0;
}
