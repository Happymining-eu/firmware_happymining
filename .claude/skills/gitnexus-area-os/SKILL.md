---
name: gitnexus-area-os
description: "Skill for the Os area of firmware_happymining. 191 symbols across 17 files."
---

# Os

191 symbols | 17 files | Cohesion: 62%

## When to Use

- Working with code in `tests/`
- Understanding how other_key, pubkey_file, release_key work
- Modifying os-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `tests/os/test_install.py` | test_rollback_without_history_is_refused, install, installed_root, need_root, test_api_url_is_not_written_without_the_option (+38) |
| `tests/os/test_render_seed.py` | test_dedicated_data_disk_needs_its_own_identity_and_confirmation, test_no_password_option_exists, test_renders_a_private_per_machine_seed, test_several_public_keys_are_all_installed, args (+12) |
| `tests/os/hm_os_testlib.py` | load_versions, make_ed25519_pubkey_line, make_key, run, yaml_load (+11) |
| `tests/os/test_disk_guard.py` | guard, stubs, test_passes_for_the_expected_disk, test_refuses_a_different_serial, test_refuses_a_disk_that_is_too_small (+8) |
| `tests/os/test_build_iso_flow.py` | make_fake_base_iso, test_base_image_that_does_not_match_the_signed_list_is_refused, test_build_installer_reports_the_image_only_when_it_exists, test_missing_base_image_or_signing_choice_is_a_skip, test_missing_entry_for_the_pinned_file_name_is_refused (+7) |
| `tests/os/test_validate.py` | good_generic, test_grub_fixture_with_auto_confirm_is_caught, test_static_bad_fixtures_are_caught, test_usage_errors_exit_2, good_unattended (+6) |
| `tests/os/test_generic_seed.py` | test_console_banner_explains_pairing_without_secrets, test_repository_files_validate_with_the_official_schema, test_generic_seed_is_valid, generic, test_agent_package_comes_from_the_medium_and_first_boot_unit_is_enabled (+5) |
| `tests/os/test_secret_scan.py` | test_clean_tree_passes, test_everything_that_goes_into_the_image_or_the_bundles_is_clean, test_findings_are_redacted, test_planted_secret_is_found, test_secret_in_a_large_binary_file_is_found (+4) |
| `tests/os/test_build_installer.py` | test_allow_partial_builds_the_seed_bundle_and_reports_the_iso_as_not_built, test_build_iso_dry_run_shows_the_repack_and_the_verification_chain, test_bundles_are_reproducible, test_dry_run_writes_nothing, test_install_scripts_bundle_is_self_contained (+3) |
| `tests/os/test_release.py` | test_dev_key_dry_run_creates_nothing, test_install_sh_accepts_what_make_checksums_produced, test_make_checksums_dry_run_and_errors, dist, test_checksums_and_signature_round_trip (+3) |

## Entry Points

Start here when exploring this area:

- **`other_key`** (Function) — `tests/os/conftest.py:53`
- **`pubkey_file`** (Function) — `tests/os/conftest.py:79`
- **`release_key`** (Function) — `tests/os/conftest.py:47`
- **`versions`** (Function) — `tests/os/conftest.py:27`
- **`load_versions`** (Function) — `tests/os/hm_os_testlib.py:74`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `other_key` | Function | `tests/os/conftest.py` | 53 |
| `pubkey_file` | Function | `tests/os/conftest.py` | 79 |
| `release_key` | Function | `tests/os/conftest.py` | 47 |
| `versions` | Function | `tests/os/conftest.py` | 27 |
| `load_versions` | Function | `tests/os/hm_os_testlib.py` | 74 |
| `make_ed25519_pubkey_line` | Function | `tests/os/hm_os_testlib.py` | 229 |
| `make_key` | Function | `tests/os/hm_os_testlib.py` | 103 |
| `run` | Function | `tests/os/hm_os_testlib.py` | 34 |
| `yaml_load` | Function | `tests/os/hm_os_testlib.py` | 253 |
| `test_allow_partial_builds_the_seed_bundle_and_reports_the_iso_as_not_built` | Function | `tests/os/test_build_installer.py` | 17 |
| `test_build_iso_dry_run_shows_the_repack_and_the_verification_chain` | Function | `tests/os/test_build_installer.py` | 117 |
| `test_bundles_are_reproducible` | Function | `tests/os/test_build_installer.py` | 59 |
| `test_dry_run_writes_nothing` | Function | `tests/os/test_build_installer.py` | 84 |
| `test_install_scripts_bundle_is_self_contained` | Function | `tests/os/test_build_installer.py` | 67 |
| `test_invalid_autoinstall_file_stops_the_build` | Function | `tests/os/test_build_installer.py` | 92 |
| `test_without_allow_partial_the_exit_code_is_77` | Function | `tests/os/test_build_installer.py` | 50 |
| `make_fake_base_iso` | Function | `tests/os/test_build_iso_flow.py` | 26 |
| `test_base_image_that_does_not_match_the_signed_list_is_refused` | Function | `tests/os/test_build_iso_flow.py` | 142 |
| `test_build_installer_reports_the_image_only_when_it_exists` | Function | `tests/os/test_build_iso_flow.py` | 197 |
| `test_missing_base_image_or_signing_choice_is_a_skip` | Function | `tests/os/test_build_iso_flow.py` | 182 |

## How to Explore

1. `context({name: "other_key"})` — see callers and callees
2. `query({search_query: "os"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
