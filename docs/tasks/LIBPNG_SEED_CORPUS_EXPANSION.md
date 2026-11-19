# Libpng seed-corpus expansion

**Status:** Descriptor-anchored preparation fix committed at `188c27ed6ca9e36eae427ad50985761bf9ecbbb5`; owner-side WSL revalidation of that exact commit is pending. Earlier native corpus and coverage results are summarized in [PR #11](https://github.com/void7x/kekkai/pull/11) and are not validation of the latest preparation fix.
**Base:** `development` at `64db5c3050fd68ac601dd189b89b1c6e3f574e0e`
**Branch:** `feature/libpng-seed-corpus`

## 1. Reason

The 2026-11-19 bounded campaign completed successfully but produced no crash or hang observation. Its launch-time seed manifest recorded ten inputs. The existing set covers malformed/truncated data, resource limits, one ordinary RGBA8 image and one small Adam7 RGBA8 image. It does not intentionally sample several PNG color-type and bit-depth combinations.

Repeating the same corpus would provide little new information. This task adds deterministic, locally generated PNG inputs while keeping the original corpus and prior campaign evidence unchanged.

## 2. Added input families

Eight supplemental fixtures are generated with only the Python standard library:

| Fixture | Input property |
|---|---|
| `grayscale_1bit.png` | Packed 1-bit grayscale samples and non-byte-aligned scanlines |
| `grayscale_4bit.png` | Packed 4-bit grayscale samples |
| `grayscale_16bit.png` | 16-bit grayscale samples and transparency metadata |
| `rgb_16bit.png` | 16-bit RGB and image data split across multiple IDAT chunks |
| `indexed_2bit_trns.png` | Indexed color, four-entry palette and transparency table |
| `gray_alpha_8bit.png` | Grayscale with alpha channel |
| `rgba_16bit_adam7.png` | 16-bit RGBA with Adam7 interlacing |
| `rgba8_filters_ancillary.png` | RGBA8, all five PNG row filters, split IDAT and ancillary metadata |

Each generated PNG is checked for its expected IHDR values, chunk integrity, compressed image-data length and scanline semantics before publication to the new corpus directory. The filter fixture must contain filter types 0 through 4. These are candidate coverage inputs, not claims of defects.

## 3. Preservation and provenance

- The original `seeds-20261105` directory is read only and is never modified.
- The new corpus is assembled in a staging directory and published to a new destination only if it does not already exist.
- The new destination is outside the Git checkout, libpng source tree and campaign-output directory.
- The previous campaign's schema-v2 seed-manifest hash remains valid because its original seed directory is preserved.
- The adapter now points to `../kekkai-work/fuzzing/libpng-1.6.59/seeds-20261119-expanded`.
- Generated PNG binaries must not be committed to Git. Git contains only the generator, validators, tests and instructions.

## 4. Local preparation

From the repository root, after pulling this branch:

```bash
python3 scripts/prepare_libpng_seed_corpus.py \
  --source-dir ../kekkai-work/fuzzing/libpng-1.6.59/seeds-20261105
```

The command copies the original ten seeds, adds eight generated inputs, validates their semantics, computes the final seed manifest and prints the resulting SHA-256. It refuses to overwrite an existing destination.

## 5. Native validation

Run the validation-only command:

```bash
python3 scripts/validate_libpng_seed_corpus.py
```

It runs the existing harness smoke checks and AFL++ `afl-showmap` checks against all 18 inputs. It does **not** launch `afl-fuzz`.

The coverage report separates the original ten-seed baseline from the eight supplemental inputs and reports the number of additional AFL map locations contributed by the supplemental set. The coverage gate passes only when:
- all 18 seed inputs execute through the real harness and produce valid non-empty maps;
- the original baseline still demonstrates more than one distinct map;
- Adam7 coverage remains repeatable across all three measurements;
- the supplemental union contributes at least one map location not present in the baseline.

A zero incremental edge count is a failed improvement check, not a reason to run another campaign anyway.

## 5.1 Earlier native validation record

The earlier owner-reported native run prepared the expanded corpus before the descriptor-anchored preparation changes in commit `188c27ed6ca9e36eae427ad50985761bf9ecbbb5`. The report is summarized in [PR #11](https://github.com/void7x/kekkai/pull/11):

- Prepared corpus: 18 seeds, 268,238 bytes.
- Manifest SHA-256: `458db92e1fe7d4f86bb016abd9ce0d94faadc69c7a1a754fe86ac55579e8d0c7`.
- Harness smoke: 21/21 passed.
- AFL-showmap: all 18 seed maps passed; Adam7 repeatability passed.
- Supplemental seeds contributed 315 additional AFL map locations beyond the original baseline.

These results describe the corpus and coverage validation performed before the latest descriptor-anchoring fix. They do **not** establish that the preparation and cleanup changes in commit `188c27ed6ca9e36eae427ad50985761bf9ecbbb5` were exercised. Exact-commit owner-side WSL revalidation remains pending.

## 6. Current gate

The owner-approved 300-second AFL++ campaign using the expanded corpus has already completed as `campaign-20261119T162025Z-772736bb823d`. It produced no crash or hang observations. AFL queue entries remain inputs, not observations.

No additional fuzzing campaign is authorized by this task. The remaining gate is owner-side WSL revalidation of the descriptor-anchored preparation fix at commit `188c27ed6ca9e36eae427ad50985761bf9ecbbb5`. The importer must continue accepting only genuine AFL++ crash/hang outputs; do not reclassify queue entries.
