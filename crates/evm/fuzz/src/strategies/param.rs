use super::state::EvmFuzzState;
use crate::strategies::fixture_strategy;
use alloy_dyn_abi::{DynSolType, DynSolValue};
use alloy_primitives::{Address, B256, I256, U256};
use proptest::prelude::*;

/// The max length of arrays we fuzz for is 256.
const MAX_ARRAY_LEN: usize = 256;

/// Given a parameter type and configured fixtures for param name, returns a strategy for generating
/// values for that type. Fixtures can be currently generated for uint, int and address types and
/// are defined for named parameter.
///
/// For example, fixtures for parameter `owner` of type `address` can be defined in a function with
/// a `function fixture_owner() public returns (address[] memory)` signature.
///
/// Fixtures are matched on parameter name, hence fixtures defined in
/// `fixture_owner` function can be used in a fuzzed test function with a signature like
/// `function testFuzz_ownerAddress(address owner, uint amount)`.
///
/// If the type of fixtures is different than the parameter type then error is raised and a random
/// value is generated.
///
/// Works with ABI Encoder v2 tuples.
pub fn fuzz_param(
    param: &DynSolType,
    fuzz_fixtures: Option<&[DynSolValue]>,
) -> BoxedStrategy<DynSolValue> {
    match *param {
        DynSolType::Address => fixture_strategy!(
            fuzz_fixtures,
            DynSolValue::type_strategy(&DynSolType::Address).boxed()
        ),
        DynSolType::Int(n @ 8..=256) => super::IntStrategy::new(n, fuzz_fixtures)
            .prop_map(move |x| DynSolValue::Int(x, n))
            .boxed(),
        DynSolType::Uint(n @ 8..=256) => super::UintStrategy::new(n, fuzz_fixtures)
            .prop_map(move |x| DynSolValue::Uint(x, n))
            .boxed(),
        DynSolType::Function | DynSolType::Bool => DynSolValue::type_strategy(param).boxed(),
        DynSolType::Bytes => {
            fixture_strategy!(fuzz_fixtures, DynSolValue::type_strategy(&DynSolType::Bytes).boxed())
        }
        DynSolType::FixedBytes(size @ 1..=32) => fixture_strategy!(
            fuzz_fixtures,
            DynSolValue::type_strategy(&DynSolType::FixedBytes(size)).boxed()
        ),
        DynSolType::String => fixture_strategy!(
            fuzz_fixtures,
            DynSolValue::type_strategy(&DynSolType::String)
                .prop_map(move |value| {
                    DynSolValue::String(
                        value.as_str().unwrap().trim().trim_end_matches('\0').to_string(),
                    )
                })
                .boxed()
        ),
        DynSolType::Tuple(ref params) => params
            .iter()
            .map(|p| fuzz_param(p, None))
            .collect::<Vec<_>>()
            .prop_map(DynSolValue::Tuple)
            .boxed(),
        DynSolType::FixedArray(ref param, size) => {
            proptest::collection::vec(fuzz_param(param, None), size)
                .prop_map(DynSolValue::FixedArray)
                .boxed()
        }
        DynSolType::Array(ref param) => {
            proptest::collection::vec(fuzz_param(param, None), 0..MAX_ARRAY_LEN)
                .prop_map(DynSolValue::Array)
                .boxed()
        }
        _ => panic!("unsupported fuzz param type: {param}"),
    }
}

/// Given a parameter type, returns a strategy for generating values for that type, given some EVM
/// fuzz state.
///
/// Works with ABI Encoder v2 tuples.
pub fn fuzz_param_from_state(
    param: &DynSolType,
    state: &EvmFuzzState,
) -> BoxedStrategy<DynSolValue> {
    // Value strategy that uses the state.
    let value = || {
        let state = state.clone();
        // Use `Index` instead of `Selector` to not iterate over the entire dictionary.
        any::<prop::sample::Index>().prop_map(move |index| {
            let state = state.dictionary_read();
            let values = state.values();
            let index = index.index(values.len());
            *values.iter().nth(index).unwrap()
        })
    };

    // Convert the value based on the parameter type
    match *param {
        DynSolType::Address => value()
            .prop_map(move |value| DynSolValue::Address(Address::from_word(value.into())))
            .boxed(),
        DynSolType::Function => value()
            .prop_map(move |value| {
                DynSolValue::Function(alloy_primitives::Function::from_word(value.into()))
            })
            .boxed(),
        DynSolType::FixedBytes(size @ 1..=32) => value()
            .prop_map(move |mut v| {
                v[size..].fill(0);
                DynSolValue::FixedBytes(B256::from(v), size)
            })
            .boxed(),
        DynSolType::Bool => DynSolValue::type_strategy(param).boxed(),
        DynSolType::String => DynSolValue::type_strategy(param)
            .prop_map(move |value| {
                DynSolValue::String(
                    value.as_str().unwrap().trim().trim_end_matches('\0').to_string(),
                )
            })
            .boxed(),
        DynSolType::Bytes => {
            value().prop_map(move |value| DynSolValue::Bytes(value.into())).boxed()
        }
        DynSolType::Int(n @ 8..=256) => match n / 8 {
            32 => value()
                .prop_map(move |value| {
                    DynSolValue::Int(I256::from_raw(U256::from_be_bytes(value)), 256)
                })
                .boxed(),
            1..=31 => value()
                .prop_map(move |value| {
                    // Generate a uintN in the correct range, then shift it to the range of intN
                    // by subtracting 2^(N-1)
                    let uint = U256::from_be_bytes(value) % U256::from(1).wrapping_shl(n);
                    let max_int_plus1 = U256::from(1).wrapping_shl(n - 1);
                    let num = I256::from_raw(uint.wrapping_sub(max_int_plus1));
                    DynSolValue::Int(num, n)
                })
                .boxed(),
            _ => unreachable!(),
        },
        DynSolType::Uint(n @ 8..=256) => match n / 8 {
            32 => value()
                .prop_map(move |value| DynSolValue::Uint(U256::from_be_bytes(value), 256))
                .boxed(),
            1..=31 => value()
                .prop_map(move |value| {
                    DynSolValue::Uint(U256::from_be_bytes(value) % U256::from(1).wrapping_shl(n), n)
                })
                .boxed(),
            _ => unreachable!(),
        },
        DynSolType::Tuple(ref params) => params
            .iter()
            .map(|p| fuzz_param_from_state(p, state))
            .collect::<Vec<_>>()
            .prop_map(DynSolValue::Tuple)
            .boxed(),
        DynSolType::FixedArray(ref param, size) => {
            proptest::collection::vec(fuzz_param_from_state(param, state), size)
                .prop_map(DynSolValue::FixedArray)
                .boxed()
        }
        DynSolType::Array(ref param) => {
            proptest::collection::vec(fuzz_param_from_state(param, state), 0..MAX_ARRAY_LEN)
                .prop_map(DynSolValue::Array)
                .boxed()
        }
        _ => panic!("unsupported fuzz param type: {param}"),
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        strategies::{build_initial_state, fuzz_calldata, fuzz_calldata_from_state},
        FuzzFixtures,
    };
    use foundry_common::abi::get_func;
    use foundry_config::FuzzDictionaryConfig;
    use revm::db::{CacheDB, EmptyDB};

    #[test]
    fn can_fuzz_array() {
        let f = "testArray(uint64[2] calldata values)";
        let func = get_func(f).unwrap();
        let db = CacheDB::new(EmptyDB::default());
        let state = build_initial_state(&db, FuzzDictionaryConfig::default());
        let strat = proptest::prop_oneof![
            60 => fuzz_calldata(func.clone(), &FuzzFixtures::default()),
            40 => fuzz_calldata_from_state(func, &state),
        ];
        let cfg = proptest::test_runner::Config { failure_persistence: None, ..Default::default() };
        let mut runner = proptest::test_runner::TestRunner::new(cfg);
        let _ = runner.run(&strat, |_| Ok(()));
    }
}
