# PMKPIR

**PMKPIR: Parallel Multi-Keyword PIR with Interleaved Batching for Private Boolean Retrieval.**

PMKPIR is a single-server keyword Private Information Retrieval (PIR) scheme that
supports **parallel multi-keyword queries** and **universal Boolean computation**
at the same time. It is built on the BFV homomorphic encryption scheme and the
SIMD (single instruction, multiple data) batching of Microsoft SEAL. 

---

## Naming correspondence with the paper

| Name in this repository | Name in the paper                                   | Role |
| ----------------------- | --------------------------------------------------- | ---- |
| `InterleavedLayout`     | interleaved batching method (Section on IBPIR)      | BFV slot layout that batches `B` keywords in one ciphertext |
| keyword-matching scan   | IBPIR (multi-keyword PIR)                            | Parallel keyword matching in a single database traversal |
| `BooleanEvaluator` + `query_compiler` | boolean query processing method      | Extends interleaved batching to universal Boolean evaluation |
| `pmkpir` (the library)  | PMKPIR                                               | The overall scheme proposed in the paper |

The queried keywords are packed as a distinct list `KL`: each keyword occupies
exactly one logical sub-block, and repeated keyword leaves reference the same
sub-block (see `CompiledQuery::packed_keywords`).

---

## Features

- **Interleaved batching** (`InterleavedLayout`): packs `B` constant-weight keyword
  codes into a single BFV plaintext so that one database traversal matches `B`
  keywords in parallel.
- **Universal Boolean evaluation**: supports arbitrary `AND` / `OR` / `NOT`
  expressions. Small sub-expressions are compiled into a local DNF that fits the
  block workspace; larger expressions transparently fall back to a balanced-tree
  homomorphic evaluation.
- **Wide keyword domains** (`WideKeywordCodebook`): supports public keyword domains
  up to 256 bits using sparse constant-weight codewords.
- **Atomic persistence**: datasets and preprocessed plaintexts are written through
  atomic rename with SHA-256 and parameter-fingerprint validation, so caches are
  safe to reuse across runs and fail closed on corruption.
- **Noise-gate checking**: every decryption verifies the invariant noise budget so
  that a degraded BFV evaluation is reported instead of returning a wrong result.

---

## Repository layout

```
pmkpir/
├── CMakeLists.txt            # top-level build
├── README.md
├── LICENSE
├── common/                   # shared infrastructure (namespace pir::common)
│   ├── include/pir/common/   #   BFV context, dataset, Boolean AST, constant-weight
│   └── src/                  #   codes, SHA-256, keyword database, persistence
├── pmkpir/                   # the scheme (namespace pir::pmkpir)
│   ├── include/pir/pmkpir/   #   layout, query compiler, protocol, wide codebook
│   └── src/
├── tests/                    # unit tests (CTest)
└── examples/
    └── basic_boolean_query.cpp
```

---

## Dependencies

- CMake >= 3.20
- A C++20 compiler (GCC 11+ or Clang 14+)
- [Microsoft SEAL 4.1.2](https://github.com/microsoft/SEAL)
- OpenSSL (the `Crypto` component)

The project has been developed and tested on WSL2 / Ubuntu 22.04 with GCC 11.4.

---

## Building

Configure with the SEAL installation prefix on `CMAKE_PREFIX_PATH`:

```bash
cd pmkpir
cmake -S . -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_TESTING=ON \
  -DCMAKE_PREFIX_PATH="$HOME/.local/seal-4.1.2"
cmake --build build -j"$(nproc)"
```

Set `CMAKE_PREFIX_PATH` (or `SEAL_PREFIX`) to wherever SEAL 4.1.2 is installed.

---

## Running the tests

```bash
ctest --test-dir build --output-on-failure
```

There are ten test executables covering the shared infrastructure and the scheme:

- `common_types_test`, `dataset_test`, `boolean_query_test`, `constant_weight_test`,
  `keyword_database_test`, `persistence_test`
- `pmkpir_query_test` (layout + query compiler)
- `pmkpir_protocol_test` (end-to-end private Boolean retrieval, multi-fragment
  packing, fallback path)
- `wide_keyword_codebook_test`, `pmkpir_wide_domain_test` (256-bit keyword domains)

---

## Running the example

```bash
./build/pmkpir_example
```

The example evaluates the Boolean query `(k0 AND k1) OR (k2 AND NOT k1)` over a
five-document collection, retrieves the matching bitmap privately, and checks it
against the plaintext ground truth.

---

## API overview

```cpp
using Query = pir::common::BooleanQuery;

// Compile a public Boolean query into an evaluation plan.
pir::pmkpir::CompiledQuery compiled = pir::pmkpir::compile_query(
    query, /*block_count=*/4);

// Client holds the BFV keys and encrypts the query.
pir::pmkpir::Client client(parameters, /*public_domain_bits=*/16);
pir::pmkpir::EncryptedQuery request = client.create_query(compiled);

// Server preprocesses the dataset and evaluates the encrypted query.
pir::pmkpir::Server server(
    parameters, client.context(),
    client.relinearization_keys(), client.galois_keys());
pir::pmkpir::PreprocessedDatabase db = server.preprocess(dataset);
pir::pmkpir::EncryptedSelection response = server.evaluate(request, db);

// Client decrypts the matched-document bitmap.
pir::pmkpir::DecryptedSelection result =
    client.decrypt_selection(response, dataset.documents.size());
```

The retrieved `result.bitmap` marks which documents match the query; the caller
then feeds those indices into any payload-recovery backend of its choice (the
paper uses Multi-query PIRANA or SpiralStreamPack for this independent phase, which
is intentionally out of scope here).

---

## Security parameters

The default `BfvParameters` use polynomial modulus degree `N = 16384`, plain
modulus `t = 65537`, block count `B = 4`, and constant weight `k = 2`, selected at
the `tc128` security level. Every context construction re-validates the parameters
with SEAL and every decryption enforces a minimum noise budget (default 20 bits).

---

## License

See [LICENSE](LICENSE). Fill in the copyright holder name and year before
publishing.

## Citation

If you use this implementation, please cite the accompanying paper
"PMKPIR: Parallel Multi-Keyword PIR with Interleaved Batching for Private
Boolean Retrieval".
