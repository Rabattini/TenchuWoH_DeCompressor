#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <cstdint>      // Tipos (uint8_t, etc.)
#include <stdexcept>    // Para std::runtime_error
#include <algorithm>    // Para std::sort
#include <filesystem>   // Para criar diretórios (C++17)
#include <sstream>      // Para formatar nomes de arquivos
#include <iomanip>      // Para std::setw, std::setfill

// --- INCLUDES PARA CODIFICAÇÃO (Windows) ---
#include <clocale> // Para setlocale
#ifdef _WIN32
#include <windows.h> // Para SetConsoleOutputCP e CP_UTF8
#endif
// ----------------------------------------

// --- Estruturas para o Scanner ---

/**
 * @brief Resultado de uma tentativa de validação de bloco LZSS.
 * Usado pelo scanner.
 */
struct DecompressValidationResult {
    bool success = false;
    size_t consumedBytes = 0;   // Quantos bytes o bloco comprimido ocupa
    size_t decompressedSize = 0; // Tamanho dos dados descomprimidos
};

/**
 * @brief Informação sobre um bloco LZSS válido encontrado pelo scanner.
 */
struct ScanResult {
    size_t offset;
    size_t consumedSize;
    size_t decompressedSize;

    // Para ordenação
    bool operator<(const ScanResult& other) const {
        if (offset != other.offset) {
            return offset < other.offset;
        }
        // Se offsets são iguais, prefere o bloco maior (consome mais)
        return consumedSize > other.consumedSize;
    }
};

// --- Função 1: Descompressor (para EXTRAÇÃO FINAL) ---

// Esta função assume que 'block' é um bloco LZSS *perfeito* e lança
// uma exceção (throw) se algo der errado.

std::vector<uint8_t> decompressLZSSBlock(const std::vector<uint8_t>& block) {
    if (block.size() < 12) {
        throw std::runtime_error("Bloco pequeno demais para conter o header LZSS");
    }

    const uint8_t* data = block.data();
    uint32_t off_literals = *reinterpret_cast<const uint32_t*>(data + 0);
    uint32_t off_pairs = *reinterpret_cast<const uint32_t*>(data + 4);

    if (off_literals >= block.size() || off_pairs >= block.size() || off_literals < 8) {
        throw std::runtime_error("Offsets inválidos no header");
    }

    size_t flags_pos = 8;
    size_t lit_pos = off_literals;
    size_t pair_pos = off_pairs;

    std::vector<uint8_t> dict_buf(4096, 0); // 0x1000
    size_t dict_index = 1;

    std::vector<uint8_t> out;
    out.reserve(block.size() * 4); // Chute inicial

    uint32_t flag_word = 0;
    uint32_t mask = 0;

    while (true) {
        if (mask == 0) {
            mask = 0x80000000;
            if (flags_pos + 4 > off_literals) {
                // Pode ser o fim normal, mas se não for...
                if (flags_pos < off_literals)
                    std::cerr << "Warning: Fim prematuro do stream de flags." << std::endl;
                break; // Fim do stream de flags
            }
            flag_word = *reinterpret_cast<const uint32_t*>(data + flags_pos);
            flags_pos += 4;
        }

        bool bit_set = (flag_word & mask) != 0;
        mask >>= 1;

        if (bit_set) {
            if (lit_pos >= off_pairs) {
                throw std::runtime_error("Stream de literais acabou prematuramente");
            }
            uint8_t literal = data[lit_pos++];
            out.push_back(literal);
            dict_buf[dict_index] = literal;
            dict_index = (dict_index + 1) & 0xFFF;
        }
        else {
            if (pair_pos + 2 > block.size()) {
                throw std::runtime_error("Stream de pares acabou prematuramente");
            }
            uint16_t pair_val = *reinterpret_cast<const uint16_t*>(data + pair_pos);
            pair_pos += 2;

            int offset = pair_val >> 4;
            if (offset == 0) {
                break; // Terminador
            }

            int length = (pair_val & 0xF) + 2;
            for (int i = 0; i < length; i++) {
                uint8_t b = dict_buf[(offset + i) & 0xFFF];
                out.push_back(b);
                dict_buf[dict_index] = b;
                dict_index = (dict_index + 1) & 0xFFF;
            }
        }
    }
    return out;
}


// --- Função 2: Validador (para o SCANNER) ---
// 
// Esta função é "segura": ela não lança exceções, apenas retorna
// um resultado de validação. Ela roda a descompressão inteira
// para encontrar o tamanho real (consumido e descomprimido).

DecompressValidationResult validateAndGetConsumedSize(const std::vector<uint8_t>& fileBuffer, size_t startOffset) {
    // Não pode nem ler o cabeçalho
    if (startOffset + 12 > fileBuffer.size()) {
        return { false, 0, 0 };
    }

    const uint8_t* data = fileBuffer.data() + startOffset;
    size_t remainingSize = fileBuffer.size() - startOffset;

    uint32_t off_literals = *reinterpret_cast<const uint32_t*>(data + 0);
    uint32_t off_pairs = *reinterpret_cast<const uint32_t*>(data + 4);

    // Checagem de sanidade (do seu script 'scan_container')
    if (!(8 <= off_literals && off_literals <= remainingSize &&
        8 <= off_pairs && off_pairs <= remainingSize &&
        off_pairs >= off_literals)) {
        return { false, 0, 0 };
    }

    size_t flags_pos = 8;
    size_t lit_pos = off_literals;
    size_t pair_pos = off_pairs;

    std::vector<uint8_t> dict_buf(4096, 0); // 0x1000
    size_t dict_index = 1;
    size_t decompressedSize = 0;

    uint32_t flag_word = 0;
    uint32_t mask = 0;

    try {
        while (true) {
            if (mask == 0) {
                mask = 0x80000000;
                if (flags_pos + 4 > off_literals) break; // Fim do stream de flags

                flag_word = *reinterpret_cast<const uint32_t*>(data + flags_pos);
                flags_pos += 4;
            }

            bool bit_set = (flag_word & mask) != 0;
            mask >>= 1;

            if (bit_set) {
                if (lit_pos >= off_pairs) break; // Erro de stream

                uint8_t literal = data[lit_pos++];
                decompressedSize++;
                dict_buf[dict_index] = literal;
                dict_index = (dict_index + 1) & 0xFFF;
            }
            else {
                if (pair_pos + 2 > remainingSize) break; // Erro de stream

                uint16_t pair_val = *reinterpret_cast<const uint16_t*>(data + pair_pos);
                pair_pos += 2;

                int offset = pair_val >> 4;
                if (offset == 0) {
                    // Terminador! Sucesso.
                    size_t consumed = pair_pos; // O tamanho consumido é até o fim do par terminador
                    return { true, consumed, decompressedSize };
                }

                int length = (pair_val & 0xF) + 2;
                for (int i = 0; i < length; i++) {
                    uint8_t b = dict_buf[(offset + i) & 0xFFF];
                    decompressedSize++;
                    dict_buf[dict_index] = b;
                    dict_index = (dict_index + 1) & 0xFFF;
                }
            }
        }
    }
    catch (...) {
        // Pega qualquer erro de leitura fora dos limites
        return { false, 0, 0 };
    }

    // Se chegou aqui, o loop quebrou sem achar um terminador
    return { false, 0, 0 };
}

// --- Função 3: O Scanner (do 'scan_container') ---

std::vector<ScanResult> scanContainer(const std::vector<uint8_t>& fileBuffer) {
    std::cout << "Escaneando " << fileBuffer.size() << " bytes..." << std::endl;
    std::vector<ScanResult> results;
    size_t n = fileBuffer.size();

    // 1. Encontra todos os candidatos
    for (size_t off = 0; off <= n - 12; off += 4) { // Pula de 4 em 4 bytes
        // Checagem rápida de plausibilidade (do seu script)
        const uint8_t* data = fileBuffer.data() + off;
        uint32_t ol = *reinterpret_cast<const uint32_t*>(data + 0);
        uint32_t orf = *reinterpret_cast<const uint32_t*>(data + 4);
        size_t rem = n - off;

        if (8 <= ol && ol <= rem && 8 <= orf && orf <= rem && orf >= ol) {
            // Se parece bom, faz a validação completa
            DecompressValidationResult res = validateAndGetConsumedSize(fileBuffer, off);

            if (res.success && res.consumedBytes > 0) {
                results.push_back({ off, res.consumedBytes, res.decompressedSize });
            }
        }
    }
    std::cout << "Encontrados " << results.size() << " candidatos..." << std::endl;

    // 2. Deduplicação
    std::sort(results.begin(), results.end());

    std::vector<ScanResult> finalResults;
    std::vector<std::pair<size_t, size_t>> keptRanges;

    for (const auto& r : results) {
        size_t off = r.offset;
        size_t end = r.offset + r.consumedSize;
        bool overlaps = false;

        for (const auto& k : keptRanges) {
            // se (r não termina antes de k começar) E (r não começa depois de k terminar)
            if (!(end <= k.first || off >= k.second)) {
                overlaps = true;
                break;
            }
        }

        if (!overlaps) {
            keptRanges.push_back({ off, end });
            finalResults.push_back(r);
        }
    }

    std::cout << "Scan concluído. Encontrados " << finalResults.size() << " blocos válidos." << std::endl;
    return finalResults;
}

// --- Função de Processamento (lê, escaneia, extrai) ---

bool processContainerFile(const std::string& inPath, const std::string& outDir) {
    std::cout << "Processando arquivo: " << inPath << std::endl;
    std::cout << "Salvando em: " << outDir << std::endl;

    // 1. Criar diretório de saída
    try {
        std::filesystem::create_directories(outDir);
    }
    catch (const std::exception& e) {
        std::cerr << "Erro: Nao foi possivel criar o diretorio de saida: " << e.what() << std::endl;
        return false;
    }

    // 2. Ler arquivo de entrada
    std::ifstream inFile(inPath, std::ios::binary);
    if (!inFile) {
        std::cerr << "Erro: Nao foi possivel abrir o arquivo de entrada: " << inPath << std::endl;
        return false;
    }
    std::vector<uint8_t> inputData(
        (std::istreambuf_iterator<char>(inFile)),
        std::istreambuf_iterator<char>()
    );
    inFile.close();
    if (inputData.empty()) {
        std::cerr << "Erro: O arquivo de entrada esta vazio." << std::endl;
        return false;
    }

    // 3. Escanear por blocos LZSS
    std::vector<ScanResult> blocks = scanContainer(inputData);
    if (blocks.empty()) {
        std::cout << "Nenhum bloco LZSS valido foi encontrado." << std::endl;
        return true;
    }

    // 4. Extrair cada bloco
    int n_ok = 0;
    int n_err = 0;
    for (const auto& blockInfo : blocks) {
        try {
            // Pega o bloco comprimido (raw) do buffer
            size_t off = blockInfo.offset;
            size_t end = off + blockInfo.consumedSize;
            std::vector<uint8_t> rawBlock(inputData.begin() + off, inputData.begin() + end);

            // Descomprime usando a função de extração
            std::vector<uint8_t> decompressedData = decompressLZSSBlock(rawBlock);

            // Verifica se o tamanho bate (checagem de sanidade)
            if (decompressedData.size() != blockInfo.decompressedSize) {
                std::cerr << "Warning: Tamanho descomprimido (do scan) " << blockInfo.decompressedSize
                    << " nao bate com (da extracao) " << decompressedData.size()
                    << " no offset " << off << std::endl;
            }

            // Formata o nome do arquivo de saída
            std::stringstream ss;
            ss << "chunk_off_" << std::hex << std::setfill('0') << std::setw(8) << blockInfo.offset
                << "_dec_" << std::dec << decompressedData.size() << ".bin";
            std::filesystem::path outFilePath = std::filesystem::path(outDir) / ss.str();

            // Salva o arquivo
            std::ofstream outFile(outFilePath, std::ios::binary);
            outFile.write(reinterpret_cast<const char*>(decompressedData.data()), decompressedData.size());
            outFile.close();
            n_ok++;

        }
        catch (const std::exception& e) {
            std::cerr << "Erro ao extrair bloco no offset 0x" << std::hex << blockInfo.offset << ": " << e.what() << std::endl;
            n_err++;
        }
    }

    std::cout << "Extração concluída: " << n_ok << " OK, " << n_err << " Falhas." << std::endl;
    return true;
}


/**
 * @brief Função principal
 */
int main(int argc, char* argv[]) {

    // =========================================================
    // MUDANÇA CRÍTICA: Forçar TUDO para UTF-8 (CP 65001)
    // =========================================================
#ifdef _WIN32
    // Define o locale do C/C++ para UTF-8.
    // Isso é importante para que o C++ (ex: fstream) 
    // interprete corretamente os nomes de arquivo.
    setlocale(LC_ALL, ".UTF8");

    // Define a página de código de SAÍDA do console para 65001 (UTF-8)
    // Isso faz com que 'std::cout' exiba 'ç', 'á', 'ã' corretamente.
    SetConsoleOutputCP(CP_UTF8); // CP_UTF8 é um atalho para 65001

    // Define a página de código de ENTRADA do console para 65001 (UTF-8)
    // Isso afeta 'std::cin' e 'std::getline'.
    SetConsoleCP(CP_UTF8);
#endif
    // =========================================================
    // FIM DA MUDANÇA
    // =========================================================


    // Modo: decompressor.exe -d <input_container> <output_directory>
    if (argc == 4 && std::string(argv[1]) == "-d") {
        std::string inPath = argv[2];
        std::string outDir = argv[3];
        processContainerFile(inPath, outDir);

        // Modo: Arrastar e soltar (um ou mais arquivos) no .exe
    }
    else if (argc > 1) {
        for (int i = 1; i < argc; ++i) {
            // Nota: Os 'argv' vêm do sistema. O setlocale acima
            // ajuda a 'std::filesystem::path' a entendê-los.
            std::filesystem::path inPath(argv[i]);
            std::string outDirName = inPath.filename().string() + "_decompressed";
            std::filesystem::path outDir = inPath.parent_path() / outDirName;

            processContainerFile(inPath.string(), outDir.string());
            std::cout << "---" << std::endl;
        }

        // Modo: interativo (sem argumentos)
    }
    else {
        std::cout << "--- Descompressor Tenchu Wrath of Heaven Made by Rabatini (Luke) ---\n" << std::endl;
        std::cout << "Uso:\n";
        std::cout << "  Modo 1: decompressor.exe -d <arquivo_de_entrada> <diretorio_de_saida>\n";
        std::cout << "  Modo 2: Arraste e solte um ou mais arquivos no .exe\n";
        std::cout << "  Modo 3: Arraste um arquivo para esta janela e pressione Enter:\n" << std::endl;

        std::string filePath;
        std::getline(std::cin, filePath);

        // Remove aspas
        if (!filePath.empty() && filePath.front() == '"' && filePath.back() == '"') {
            filePath = filePath.substr(1, filePath.length() - 2);
        }

        if (!filePath.empty()) {
            std::filesystem::path inPath(filePath);
            std::string outDirName = inPath.filename().string() + "_decompressed";
            std::filesystem::path outDir = inPath.parent_path() / outDirName;
            processContainerFile(inPath.string(), outDir.string());
        }
        else {
            std::cout << "Nenhum arquivo para processar. Saindo." << std::endl;
        }
    }

    std::cout << "\nConcluído. Pressione Enter para sair." << std::endl;
    std::cin.get();
    return 0;
}