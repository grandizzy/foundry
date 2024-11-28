//! Contains various tests for checking cast decode commands

use alloy_chains::NamedChain;
use alloy_network::TransactionResponse;
use alloy_rpc_types::{BlockNumberOrTag, Index};
use anvil::NodeConfig;
use foundry_test_utils::{
    casttest, forgetest, forgetest_async,
    rpc::{next_etherscan_api_key, next_rpc_endpoint},
    str,
};

casttest!(string_decode, |_prj, cmd| {
    cmd.args(["string-decode", "0x88c379a0000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000054753303235000000000000000000000000000000000000000000000000000000"]).assert_success().stdout_eq(str![[r#"
"GS025"

"#]]);
});

casttest!(event_decode, |_prj, cmd| {
    cmd.args(["decode-event", "MyEvent(uint256,address)", "0x000000000000000000000000000000000000000000000000000000000000004e0000000000000000000000000000000000000000000000000000000000d0004f"]).assert_success().stdout_eq(str![[r#"
78
0x0000000000000000000000000000000000D0004F

"#]]);
});

casttest!(error_decode_with_sig, |_prj, cmd| {
    cmd.args(["decode-error", "--sig", "AnotherValueTooHigh(uint256,address)", "0x7191bc6200000000000000000000000000000000000000000000000000000000000000650000000000000000000000000000000000000000000000000000000000D0004F"]).assert_success().stdout_eq(str![[r#"
101
0x0000000000000000000000000000000000D0004F

"#]]);
});

// tests cast can decode traces when using project artifacts
forgetest!(error_decode_with_cache, |prj, cmd| {
    foundry_test_utils::util::initialize(prj.root());
    prj.add_source(
        "LocalProjectContract",
        r#"
contract ContractWithCustomError {
    error AnotherValueTooHigh(uint256, address);
}
   "#,
    )
    .unwrap();
    // Store selectors in local cache.
    cmd.forge_fuse().args(["selectors", "cache"]).assert_success();

    // Assert cast can decode custom error with local cache.
    cmd.cast_fuse()
        .args(["decode-error", "0x7191bc6200000000000000000000000000000000000000000000000000000000000000650000000000000000000000000000000000000000000000000000000000D0004F"])
        .assert_success()
        .stdout_eq(str![[r#"
AnotherValueTooHigh(uint256,address)
101
0x0000000000000000000000000000000000D0004F

"#]]);
});

// <https://github.com/foundry-rs/foundry/issues/3473>
casttest!(test_non_mainnet_traces, |prj, cmd| {
    prj.clear();
    cmd.args([
        "run",
        "0xa003e419e2d7502269eb5eda56947b580120e00abfd5b5460d08f8af44a0c24f",
        "--rpc-url",
        next_rpc_endpoint(NamedChain::Optimism).as_str(),
        "--etherscan-api-key",
        next_etherscan_api_key(NamedChain::Optimism).as_str(),
    ])
    .assert_success()
    .stdout_eq(str![[r#"
Executing previous transactions from the block.
Traces:
  [33841] FiatTokenProxy::fallback(0x111111125421cA6dc452d289314280a0f8842A65, 164054805 [1.64e8])
    ├─ [26673] FiatTokenV2_2::approve(0x111111125421cA6dc452d289314280a0f8842A65, 164054805 [1.64e8]) [delegatecall]
    │   ├─ emit Approval(owner: 0x9a95Af47C51562acfb2107F44d7967DF253197df, spender: 0x111111125421cA6dc452d289314280a0f8842A65, value: 164054805 [1.64e8])
    │   └─ ← [Return] true
    └─ ← [Return] true
...

"#]]);
});

// tests cast can decode traces when using project artifacts
forgetest_async!(decode_traces_with_project_artifacts, |prj, cmd| {
    let (api, handle) =
        anvil::spawn(NodeConfig::test().with_disable_default_create2_deployer(true)).await;

    foundry_test_utils::util::initialize(prj.root());
    prj.add_source(
        "LocalProjectContract",
        r#"
contract LocalProjectContract {
    event LocalProjectContractCreated(address owner);

    constructor() {
        emit LocalProjectContractCreated(msg.sender);
    }
}
   "#,
    )
    .unwrap();
    prj.add_script(
        "LocalProjectScript",
        r#"
import "forge-std/Script.sol";
import {LocalProjectContract} from "../src/LocalProjectContract.sol";

contract LocalProjectScript is Script {
    function run() public {
        vm.startBroadcast();
        new LocalProjectContract();
        vm.stopBroadcast();
    }
}
   "#,
    )
    .unwrap();

    cmd.args([
        "script",
        "--private-key",
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
        "--rpc-url",
        &handle.http_endpoint(),
        "--broadcast",
        "LocalProjectScript",
    ]);

    cmd.assert_success();

    let tx_hash = api
        .transaction_by_block_number_and_index(BlockNumberOrTag::Latest, Index::from(0))
        .await
        .unwrap()
        .unwrap()
        .tx_hash();

    // Assert cast with local artifacts from outside the project.
    cmd.cast_fuse()
        .args(["run", "--la", format!("{tx_hash}").as_str(), "--rpc-url", &handle.http_endpoint()])
        .assert_success()
        .stdout_eq(str![[r#"
Executing previous transactions from the block.
Compiling project to generate artifacts
Nothing to compile

"#]]);

    // Run cast from project dir.
    cmd.cast_fuse().set_current_dir(prj.root());

    // Assert cast without local artifacts cannot decode traces.
    cmd.cast_fuse()
        .args(["run", format!("{tx_hash}").as_str(), "--rpc-url", &handle.http_endpoint()])
        .assert_success()
        .stdout_eq(str![[r#"
Executing previous transactions from the block.
Traces:
  [13520] → new <unknown>@0x5FbDB2315678afecb367f032d93F642f64180aa3
    ├─  emit topic 0: 0xa7263295d3a687d750d1fd377b5df47de69d7db8decc745aaa4bbee44dc1688d
    │           data: 0x000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb92266
    └─ ← [Return] 62 bytes of code


Transaction successfully executed.
[GAS]

"#]]);

    // Assert cast with local artifacts can decode traces.
    cmd.cast_fuse()
        .args(["run", "--la", format!("{tx_hash}").as_str(), "--rpc-url", &handle.http_endpoint()])
        .assert_success()
        .stdout_eq(str![[r#"
Executing previous transactions from the block.
Compiling project to generate artifacts
No files changed, compilation skipped
Traces:
  [13520] → new LocalProjectContract@0x5FbDB2315678afecb367f032d93F642f64180aa3
    ├─ emit LocalProjectContractCreated(owner: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266)
    └─ ← [Return] 62 bytes of code


Transaction successfully executed.
[GAS]

"#]]);
});

// tests cast can decode traces when running with verbosity level > 4
forgetest_async!(show_state_changes_in_traces, |prj, cmd| {
    let (api, handle) = anvil::spawn(NodeConfig::test()).await;

    foundry_test_utils::util::initialize(prj.root());
    // Deploy counter contract.
    cmd.args([
        "script",
        "--private-key",
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
        "--rpc-url",
        &handle.http_endpoint(),
        "--broadcast",
        "CounterScript",
    ])
    .assert_success();

    // Send tx to change counter storage value.
    cmd.cast_fuse()
        .args([
            "send",
            "0x5FbDB2315678afecb367f032d93F642f64180aa3",
            "setNumber(uint256)",
            "111",
            "--private-key",
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
            "--rpc-url",
            &handle.http_endpoint(),
        ])
        .assert_success();

    let tx_hash = api
        .transaction_by_block_number_and_index(BlockNumberOrTag::Latest, Index::from(0))
        .await
        .unwrap()
        .unwrap()
        .tx_hash();

    // Assert cast with verbosity displays storage changes.
    cmd.cast_fuse()
        .args([
            "run",
            format!("{tx_hash}").as_str(),
            "-vvvvv",
            "--rpc-url",
            &handle.http_endpoint(),
        ])
        .assert_success()
        .stdout_eq(str![[r#"
Executing previous transactions from the block.
Traces:
  [22287] 0x5FbDB2315678afecb367f032d93F642f64180aa3::setNumber(111)
    ├─  storage changes:
    │   @ 0: 0 → 111
    └─ ← [Stop] 


Transaction successfully executed.
[GAS]

"#]]);
});
