//! general eth api tests

use crate::abi::Greeter;
use alloy_primitives::{address, Bytes, Uint, U256};
use alloy_provider::Provider;
use alloy_rpc_types::BlockId;
use anvil::{spawn, NodeConfig};
use foundry_test_utils::rpc::next_http_rpc_endpoint;
use std::fs;

#[tokio::test(flavor = "multi_thread")]
async fn can_load_state() {
    let tmp = tempfile::tempdir().unwrap();
    let state_file = tmp.path().join("state.json");

    let (api, _handle) = spawn(NodeConfig::test()).await;

    api.mine_one().await;
    api.mine_one().await;

    let num = api.block_number().unwrap();

    let state = api.serialized_state(false).await.unwrap();
    foundry_common::fs::write_json_file(&state_file, &state).unwrap();

    let (api, _handle) = spawn(NodeConfig::test().with_init_state_path(state_file)).await;

    let num2 = api.block_number().unwrap();

    // Ref: https://github.com/foundry-rs/foundry/issues/9017
    // Check responses of eth_blockNumber and eth_getBlockByNumber don't deviate after loading state
    let num_from_tag = api
        .block_by_number(alloy_eips::BlockNumberOrTag::Latest)
        .await
        .unwrap()
        .unwrap()
        .header
        .number;
    assert_eq!(num, num2);

    assert_eq!(num, U256::from(num_from_tag));
}

#[tokio::test(flavor = "multi_thread")]
async fn can_load_existing_state_legacy() {
    let state_file = "test-data/state-dump-legacy.json";

    let (api, _handle) = spawn(NodeConfig::test().with_init_state_path(state_file)).await;

    let block_number = api.block_number().unwrap();
    assert_eq!(block_number, Uint::from(2));
}

#[tokio::test(flavor = "multi_thread")]
async fn can_load_existing_state_legacy_stress() {
    let state_file = "test-data/state-dump-legacy-stress.json";

    let (api, _handle) = spawn(NodeConfig::test().with_init_state_path(state_file)).await;

    let block_number = api.block_number().unwrap();
    assert_eq!(block_number, Uint::from(5));
}

#[tokio::test(flavor = "multi_thread")]
async fn can_load_existing_state() {
    let state_file = "test-data/state-dump.json";

    let (api, _handle) = spawn(NodeConfig::test().with_init_state_path(state_file)).await;

    let block_number = api.block_number().unwrap();
    assert_eq!(block_number, Uint::from(2));
}

#[tokio::test(flavor = "multi_thread")]
async fn test_make_sure_historical_state_is_not_cleared_on_dump() {
    let tmp = tempfile::tempdir().unwrap();
    let state_file = tmp.path().join("state.json");

    let (api, handle) = spawn(NodeConfig::test()).await;

    let provider = handle.http_provider();

    let greeter = Greeter::deploy(&provider, "Hello".to_string()).await.unwrap();

    let address = greeter.address();

    let _tx = greeter
        .setGreeting("World!".to_string())
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

    api.mine_one().await;

    let ser_state = api.serialized_state(true).await.unwrap();
    foundry_common::fs::write_json_file(&state_file, &ser_state).unwrap();

    let block_number = api.block_number().unwrap();
    assert_eq!(block_number, Uint::from(3));

    // Makes sure historical states of the new instance are not cleared.
    let code = provider.get_code_at(*address).block_id(BlockId::number(2)).await.unwrap();

    assert_ne!(code, Bytes::new());
}

#[tokio::test(flavor = "multi_thread")]
async fn can_preserve_historical_states_between_dump_and_load() {
    let tmp = tempfile::tempdir().unwrap();
    let state_file = tmp.path().join("state.json");

    let (api, handle) = spawn(NodeConfig::test()).await;

    let provider = handle.http_provider();

    let greeter = Greeter::deploy(&provider, "Hello".to_string()).await.unwrap();

    let address = greeter.address();

    let deploy_blk_num = provider.get_block_number().await.unwrap();

    let tx = greeter
        .setGreeting("World!".to_string())
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

    let change_greeting_blk_num = tx.block_number.unwrap();

    api.mine_one().await;

    let ser_state = api.serialized_state(true).await.unwrap();
    foundry_common::fs::write_json_file(&state_file, &ser_state).unwrap();

    let (api, handle) = spawn(NodeConfig::test().with_init_state_path(state_file)).await;

    let block_number = api.block_number().unwrap();
    assert_eq!(block_number, Uint::from(3));

    let provider = handle.http_provider();

    let greeter = Greeter::new(*address, provider);

    let greeting_at_init =
        greeter.greet().block(BlockId::number(deploy_blk_num)).call().await.unwrap()._0;

    assert_eq!(greeting_at_init, "Hello");

    let greeting_after_change =
        greeter.greet().block(BlockId::number(change_greeting_blk_num)).call().await.unwrap()._0;

    assert_eq!(greeting_after_change, "World!");
}

// see <https://github.com/foundry-rs/foundry/issues/9053>
#[tokio::test(flavor = "multi_thread")]
async fn can_preserve_account_balance_on_restarts() {
    let tmp = tempfile::tempdir().unwrap();
    let state_file = tmp.path().join("state.json");
    fs::write(state_file.as_path(), r#"{"block":{"number":"0x1","coinbase":"0x0000000000000000000000000000000000000000","timestamp":"0x6720ca48","gas_limit":"0x1c9c380","basefee":"0x3b9aca00","difficulty":"0x0","prevrandao":"0xe1267ef1ba24d969578e6f64331f39aefa41dd9e3269e9cdb08997e822cfb02c","blob_excess_gas_and_price":{"excess_blob_gas":0,"blob_gasprice":1}},"accounts":{"0x0000000000000000000000000000000000000000":{"nonce":0,"balance":"0x5208","code":"0x","storage":{}},"0x14dc79964da2c08b23698b3d3cc7ca32193d9955":{"nonce":0,"balance":"0x21e19e0c9bab2400000","code":"0x","storage":{}},"0x15d34aaf54267db7d7c367839aaf71a00a2c6a65":{"nonce":0,"balance":"0x21e19e0c9bab2400000","code":"0x","storage":{}},"0x23618e81e3f5cdf7f54c3d65f7fbc0abf5b21e8f":{"nonce":0,"balance":"0x21e19e0c9bab2400000","code":"0x","storage":{}},"0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc":{"nonce":0,"balance":"0x21e19e0c9bab2400000","code":"0x","storage":{}},"0x4e59b44847b379578588920ca78fbf26c0b4956c":{"nonce":0,"balance":"0x0","code":"0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe03601600081602082378035828234f58015156039578182fd5b8082525050506014600cf3","storage":{}},"0x70997970c51812dc3a010c7d01b50e0d17dc79c8":{"nonce":0,"balance":"0x21e19e0c9bab2400000","code":"0x","storage":{}},"0x90f79bf6eb2c4f870365e785982e1f101e93b906":{"nonce":0,"balance":"0x21e19e0c9bab2400000","code":"0x","storage":{}},"0x9276449eac5b4f7bc17cfc6700f7beeb86f9bcd0":{"nonce":0,"balance":"0xde0b6b3a7640000","code":"0x","storage":{}},"0x976ea74026e726554db657fa54763abd0c3a0aa9":{"nonce":0,"balance":"0x21e19e0c9bab2400000","code":"0x","storage":{}},"0x9965507d1a55bcc2695c58ba16fb37d819b0a4dc":{"nonce":0,"balance":"0x21e19e0c9bab2400000","code":"0x","storage":{}},"0xa0ee7a142d267c1f36714e4a8f75612f20a79720":{"nonce":0,"balance":"0x21e19e0c9bab2400000","code":"0x","storage":{}},"0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266":{"nonce":1,"balance":"0x21e0bffffed99515df8","code":"0x","storage":{}}},"best_block_number":"0x1","blocks":[{"header":{"parentHash":"0x0000000000000000000000000000000000000000000000000000000000000000","ommersHash":"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347","beneficiary":"0x0000000000000000000000000000000000000000","stateRoot":"0x0000000000000000000000000000000000000000000000000000000000000000","transactionsRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421","receiptsRoot":"0x0000000000000000000000000000000000000000000000000000000000000000","logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","difficulty":"0x0","number":"0x0","gasLimit":"0x1c9c380","gasUsed":"0x0","timestamp":"0x6720ca44","mixHash":"0x0000000000000000000000000000000000000000000000000000000000000000","nonce":"0x0000000000000000","baseFeePerGas":"0x3b9aca00","blobGasUsed":"0x0","excessBlobGas":"0x0","extraData":"0x"},"transactions":[],"ommers":[]},{"header":{"parentHash":"0x0000000000000000000000000000000000000000000000000000000000000000","ommersHash":"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347","beneficiary":"0x0000000000000000000000000000000000000000","stateRoot":"0x0000000000000000000000000000000000000000000000000000000000000000","transactionsRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421","receiptsRoot":"0x0000000000000000000000000000000000000000000000000000000000000000","logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","difficulty":"0x0","number":"0x0","gasLimit":"0x1c9c380","gasUsed":"0x0","timestamp":"0x6720ca4c","mixHash":"0x0000000000000000000000000000000000000000000000000000000000000000","nonce":"0x0000000000000000","baseFeePerGas":"0x3b9aca00","blobGasUsed":"0x0","excessBlobGas":"0x0","extraData":"0x"},"transactions":[],"ommers":[]},{"header":{"parentHash":"0x85d942e2f927e3721d3b7d082f91ac2a4182c78f3dfea92cae02b2375f872433","ommersHash":"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347","beneficiary":"0x0000000000000000000000000000000000000000","stateRoot":"0xbb8da6afb9aafe5ad6b24ee1af9cac0bd8bde8a7b8a555534c2a76ba65118204","transactionsRoot":"0x6302360baf54081841560803d38228fe5e8cc2219b9e21c28d0114b11aa7aaa2","receiptsRoot":"0xf78dfb743fbd92ade140711c8bbc542b5e307f0ab7984eff35d751969fe57efa","logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","difficulty":"0x0","number":"0x1","gasLimit":"0x1c9c380","gasUsed":"0x5208","timestamp":"0x6720ca48","mixHash":"0x0000000000000000000000000000000000000000000000000000000000000000","nonce":"0x0000000000000000","baseFeePerGas":"0x3b9aca00","blobGasUsed":"0x0","excessBlobGas":"0x0","extraData":"0x"},"transactions":[{"transaction":{"EIP1559":{"chainId":"0x7a69","nonce":"0x0","gas":"0x5209","maxFeePerGas":"0x77359401","maxPriorityFeePerGas":"0x1","to":"0x9276449eac5b4f7bc17cfc6700f7beeb86f9bcd0","value":"0xde0b6b3a7640000","accessList":[],"input":"0x","r":"0x6262b4d61aa3182c51b031dc29453e1bd06436630e43737f80e91e244c5dc2d6","s":"0x7bf5e4a2e1c996ae7f822f2f69b2f0ceee8aa7d325cba4b0c9a5213299edd132","yParity":"0x0","hash":"0xa2aef483bae39492938b76074cabce595e462b88064e8d5e3f1b22ee082580b4"}},"impersonated_sender":null}],"ommers":[]}],"transactions":[{"info":{"transaction_hash":"0xa2aef483bae39492938b76074cabce595e462b88064e8d5e3f1b22ee082580b4","transaction_index":0,"from":"0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266","to":"0x9276449eac5b4f7bc17cfc6700f7beeb86f9bcd0","contract_address":null,"traces":[{"parent":null,"children":[],"idx":0,"trace":{"depth":0,"success":true,"caller":"0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266","address":"0x9276449eac5b4f7bc17cfc6700f7beeb86f9bcd0","maybe_precompile":null,"selfdestruct_address":null,"selfdestruct_refund_target":null,"selfdestruct_transferred_value":null,"kind":"CALL","value":"0xde0b6b3a7640000","data":"0x","output":"0x","gas_used":0,"gas_limit":1,"status":"Stop","steps":[],"decoded":{"label":null,"return_data":null,"call_data":null}},"logs":[],"ordering":[]}],"exit":"Stop","out":"0x","nonce":0,"gas_used":21000},"receipt":{"type":"0x2","status":"0x1","cumulativeGasUsed":"0x5208","logs":[],"logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"},"block_hash":"0xe14c442b4ab5e6fde84530ee3503be2e382c7c3096d5bb24d53c5ccfb9944d62","block_number":1}],"historical_states":null}"#).expect("Unable to write state file");

    let (api, _) = spawn(
        NodeConfig::test()
            .with_eth_rpc_url(Some(next_http_rpc_endpoint()))
            .with_chain_id(Some(31337u64))
            .with_init_state_path(state_file),
    )
    .await;
    let balance =
        api.balance(address!("9276449EaC5b4f7Bc17cFC6700f7BeeB86F9bCd0"), None).await.unwrap();
    assert_eq!(balance, U256::from(1e18 as u64));
}
