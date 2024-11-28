//! Contains various tests for checking cast wallet commands

use alloy_primitives::{b256, B256};
use foundry_test_utils::{casttest, str, util::OutputExt};
use std::{fs, path::Path, str::FromStr};

// tests that we can create a new wallet with keystore
casttest!(new_wallet_keystore_with_password, |_prj, cmd| {
    cmd.args(["wallet", "new", ".", "--unsafe-password", "test"]).assert_success().stdout_eq(str![
        [r#"
Created new encrypted keystore file: [..]
[ADDRESS]

"#]
    ]);
});

// tests that we can get the address of a keystore file
casttest!(wallet_address_keystore_with_password_file, |_prj, cmd| {
    let keystore_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/keystore");

    cmd.args([
        "wallet",
        "address",
        "--keystore",
        keystore_dir
            .join("UTC--2022-12-20T10-30-43.591916000Z--ec554aeafe75601aaab43bd4621a22284db566c2")
            .to_str()
            .unwrap(),
        "--password-file",
        keystore_dir.join("password-ec554").to_str().unwrap(),
    ])
    .assert_success()
    .stdout_eq(str![[r#"
0xeC554aeAFE75601AaAb43Bd4621A22284dB566C2

"#]]);
});

// tests that `cast wallet sign message` outputs the expected signature
casttest!(wallet_sign_message_utf8_data, |_prj, cmd| {
    let pk = "0x0000000000000000000000000000000000000000000000000000000000000001";
    let address = "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf";
    let msg = "test";
    let expected = "0xfe28833983d6faa0715c7e8c3873c725ddab6fa5bf84d40e780676e463e6bea20fc6aea97dc273a98eb26b0914e224c8dd5c615ceaab69ddddcf9b0ae3de0e371c";

    cmd.args(["wallet", "sign", "--private-key", pk, msg]).assert_success().stdout_eq(str![[r#"
0xfe28833983d6faa0715c7e8c3873c725ddab6fa5bf84d40e780676e463e6bea20fc6aea97dc273a98eb26b0914e224c8dd5c615ceaab69ddddcf9b0ae3de0e371c

"#]]);

    // Success.
    cmd.cast_fuse()
        .args(["wallet", "verify", "-a", address, msg, expected])
        .assert_success()
        .stdout_eq(str![[r#"
Validation succeeded. Address 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf signed this message.

"#]]);

    // Fail.
    cmd.cast_fuse()
        .args(["wallet", "verify", "-a", address, "other msg", expected])
        .assert_failure()
        .stderr_eq(str![[r#"
Error: Validation failed. Address 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf did not sign this message.

"#]]);
});

// tests that `cast wallet sign message` outputs the expected signature, given a 0x-prefixed data
casttest!(wallet_sign_message_hex_data, |_prj, cmd| {
    cmd.args([
        "wallet",
        "sign",
        "--private-key",
        "0x0000000000000000000000000000000000000000000000000000000000000001",
        "0x0000000000000000000000000000000000000000000000000000000000000000",
    ]).assert_success().stdout_eq(str![[r#"
0x23a42ca5616ee730ff3735890c32fc7b9491a9f633faca9434797f2c845f5abf4d9ba23bd7edb8577acebaa3644dc5a4995296db420522bb40060f1693c33c9b1c

"#]]);
});

// tests that `cast wallet sign typed-data` outputs the expected signature, given a JSON string
casttest!(wallet_sign_typed_data_string, |_prj, cmd| {
    cmd.args([
        "wallet",
        "sign",
        "--private-key",
        "0x0000000000000000000000000000000000000000000000000000000000000001",
        "--data",
        "{\"types\": {\"EIP712Domain\": [{\"name\": \"name\",\"type\": \"string\"},{\"name\": \"version\",\"type\": \"string\"},{\"name\": \"chainId\",\"type\": \"uint256\"},{\"name\": \"verifyingContract\",\"type\": \"address\"}],\"Message\": [{\"name\": \"data\",\"type\": \"string\"}]},\"primaryType\": \"Message\",\"domain\": {\"name\": \"example.metamask.io\",\"version\": \"1\",\"chainId\": \"1\",\"verifyingContract\": \"0x0000000000000000000000000000000000000000\"},\"message\": {\"data\": \"Hello!\"}}",
    ]).assert_success().stdout_eq(str![[r#"
0x06c18bdc8163219fddc9afaf5a0550e381326474bb757c86dc32317040cf384e07a2c72ce66c1a0626b6750ca9b6c035bf6f03e7ed67ae2d1134171e9085c0b51b

"#]]);
});

// tests that `cast wallet sign typed-data` outputs the expected signature, given a JSON file
casttest!(wallet_sign_typed_data_file, |_prj, cmd| {
    cmd.args([
        "wallet",
        "sign",
        "--private-key",
        "0x0000000000000000000000000000000000000000000000000000000000000001",
        "--data",
        "--from-file",
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/sign_typed_data.json")
            .into_os_string()
            .into_string()
            .unwrap()
            .as_str(),
    ]).assert_success().stdout_eq(str![[r#"
0x06c18bdc8163219fddc9afaf5a0550e381326474bb757c86dc32317040cf384e07a2c72ce66c1a0626b6750ca9b6c035bf6f03e7ed67ae2d1134171e9085c0b51b

"#]]);
});

// tests that `cast wallet sign-auth message` outputs the expected signature
casttest!(wallet_sign_auth, |_prj, cmd| {
    cmd.args([
        "wallet",
        "sign-auth",
        "--private-key",
        "0x0000000000000000000000000000000000000000000000000000000000000001",
        "--nonce",
        "100",
        "--chain",
        "1",
        "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"]).assert_success().stdout_eq(str![[r#"
0xf85a01947e5f4552091a69125d5dfcb7b8c2659029395bdf6401a0ad489ee0314497c3f06567f3080a46a63908edc1c7cdf2ac2d609ca911212086a065a6ba951c8748dd8634740fe498efb61770097d99ff5fdcb9a863b62ea899f6

"#]]);
});

// tests that `cast wallet list` outputs the local accounts
casttest!(wallet_list_local_accounts, |prj, cmd| {
    let keystore_path = prj.root().join("keystore");
    fs::create_dir_all(keystore_path).unwrap();
    cmd.set_current_dir(prj.root());

    // empty results
    cmd.cast_fuse()
        .args(["wallet", "list", "--dir", "keystore"])
        .assert_success()
        .stdout_eq(str![""]);

    // create 10 wallets
    cmd.cast_fuse()
        .args(["wallet", "new", "keystore", "-n", "10", "--unsafe-password", "test"])
        .assert_success()
        .stdout_eq(str![[r#"
Created new encrypted keystore file: [..]
[ADDRESS]
Created new encrypted keystore file: [..]
[ADDRESS]
Created new encrypted keystore file: [..]
[ADDRESS]
Created new encrypted keystore file: [..]
[ADDRESS]
Created new encrypted keystore file: [..]
[ADDRESS]
Created new encrypted keystore file: [..]
[ADDRESS]
Created new encrypted keystore file: [..]
[ADDRESS]
Created new encrypted keystore file: [..]
[ADDRESS]
Created new encrypted keystore file: [..]
[ADDRESS]
Created new encrypted keystore file: [..]
[ADDRESS]

"#]]);

    // test list new wallet
    cmd.cast_fuse().args(["wallet", "list", "--dir", "keystore"]).assert_success().stdout_eq(str![
        [r#"
[..] (Local)
[..] (Local)
[..] (Local)
[..] (Local)
[..] (Local)
[..] (Local)
[..] (Local)
[..] (Local)
[..] (Local)
[..] (Local)

"#]
    ]);
});

// tests that `cast wallet new-mnemonic --entropy` outputs the expected mnemonic
casttest!(wallet_mnemonic_from_entropy, |_prj, cmd| {
    cmd.args([
        "wallet",
        "new-mnemonic",
        "--accounts",
        "3",
        "--entropy",
        "0xdf9bf37e6fcdf9bf37e6fcdf9bf37e3c",
    ])
    .assert_success()
    .stdout_eq(str![[r#"
Generating mnemonic from provided entropy...
Successfully generated a new mnemonic.
Phrase:
test test test test test test test test test test test junk

Accounts:
- Account 0:
Address:     0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
Private key: 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

- Account 1:
Address:     0x70997970C51812dc3A010C7d01b50e0d17dc79C8
Private key: 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d

- Account 2:
Address:     0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC
Private key: 0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a


"#]]);
});

// tests that `cast wallet new-mnemonic --json` outputs the expected mnemonic
casttest!(wallet_mnemonic_from_entropy_json, |_prj, cmd| {
    cmd.args([
        "wallet",
        "new-mnemonic",
        "--accounts",
        "3",
        "--entropy",
        "0xdf9bf37e6fcdf9bf37e6fcdf9bf37e3c",
        "--json",
    ])
    .assert_success()
    .stdout_eq(str![[r#"
{
  "mnemonic": "test test test test test test test test test test test junk",
  "accounts": [
    {
      "address": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
      "private_key": "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    },
    {
      "address": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
      "private_key": "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
    },
    {
      "address": "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
      "private_key": "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"
    }
  ]
}

"#]]);
});

// tests that `cast wallet private-key` with arguments outputs the private key
casttest!(wallet_private_key_from_mnemonic_arg, |_prj, cmd| {
    cmd.args([
        "wallet",
        "private-key",
        "test test test test test test test test test test test junk",
        "1",
    ])
    .assert_success()
    .stdout_eq(str![[r#"
0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d

"#]]);
});

// tests that `cast wallet private-key` with options outputs the private key
casttest!(wallet_private_key_from_mnemonic_option, |_prj, cmd| {
    cmd.args([
        "wallet",
        "private-key",
        "--mnemonic",
        "test test test test test test test test test test test junk",
        "--mnemonic-index",
        "1",
    ])
    .assert_success()
    .stdout_eq(str![[r#"
0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d

"#]]);
});

// tests that `cast wallet private-key` with derivation path outputs the private key
casttest!(wallet_private_key_with_derivation_path, |_prj, cmd| {
    cmd.args([
        "wallet",
        "private-key",
        "--mnemonic",
        "test test test test test test test test test test test junk",
        "--mnemonic-derivation-path",
        "m/44'/60'/0'/0/1",
    ])
    .assert_success()
    .stdout_eq(str![[r#"
0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d

"#]]);
});

// tests that `cast wallet import` creates a keystore for a private key and that `cast wallet
// decrypt-keystore` can access it
casttest!(wallet_import_and_decrypt, |prj, cmd| {
    let keystore_path = prj.root().join("keystore");

    cmd.set_current_dir(prj.root());

    let account_name = "testAccount";

    // Default Anvil private key
    let test_private_key =
        b256!("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");

    // import private key
    cmd.cast_fuse()
        .args([
            "wallet",
            "import",
            account_name,
            "--private-key",
            &test_private_key.to_string(),
            "-k",
            "keystore",
            "--unsafe-password",
            "test",
        ])
        .assert_success()
        .stdout_eq(str![[r#"
`testAccount` keystore was saved successfully. [ADDRESS]

"#]]);

    // check that the keystore file was created
    let keystore_file = keystore_path.join(account_name);

    assert!(keystore_file.exists());

    // decrypt the keystore file
    let decrypt_output = cmd.cast_fuse().args([
        "wallet",
        "decrypt-keystore",
        account_name,
        "-k",
        "keystore",
        "--unsafe-password",
        "test",
    ]);

    // get the PK out of the output (last word in the output)
    let decrypt_output = decrypt_output.assert_success().get_output().stdout_lossy();
    let private_key_string = decrypt_output.split_whitespace().last().unwrap();
    // check that the decrypted private key matches the imported private key
    let decrypted_private_key = B256::from_str(private_key_string).unwrap();
    // the form
    assert_eq!(decrypted_private_key, test_private_key);
});
