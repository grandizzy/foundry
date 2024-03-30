// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";

struct FuzzSelector {
    address addr;
    bytes4[] selectors;
}

contract Owned {
    address public owner;
    address private ownerCandidate;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    modifier onlyOwnerCandidate() {
        require(msg.sender == ownerCandidate);
        _;
    }

    function transferOwnership(address candidate) external onlyOwner {
        ownerCandidate = candidate;
    }

    function acceptOwnership() external onlyOwnerCandidate {
        owner = ownerCandidate;
    }
}

contract Handler is Test {
    Owned owned;

    constructor(Owned _owned) {
        owned = _owned;
    }

    function transferOwnership(address sender, address candidate) external {
        vm.incrementMetrics("transferOwnership");
        vm.incrementMetrics(
            string.concat("transferOwnership.sender.", vm.toString(sender))
        );
        vm.incrementMetrics(
            string.concat(
                "transferOwnership.candidate.",
                vm.toString(candidate)
            )
        );

        vm.assume(sender != address(0));
        vm.prank(sender);
        try owned.transferOwnership(candidate) {} catch {
            vm.incrementMetrics("onlyOwner");
        }
    }

    function acceptOwnership(address sender) external {
        vm.incrementMetrics("acceptOwnership");
        vm.incrementMetrics(
            string.concat("acceptOwnership.sender.", vm.toString(sender))
        );

        vm.assume(sender != address(0));
        vm.prank(sender);
        try owned.acceptOwnership() {} catch {
            vm.incrementMetrics("onlyOwnerCandidate");
        }
    }
}

contract TransferSequenceWithMetrics is Test {
    address owner;
    Owned owned;
    Handler handler;

    function setUp() public {
        owner = address(this);
        owned = new Owned();
        handler = new Handler(owned);

        bytes4[] memory selectors = new bytes4[](2);
        selectors[0] = handler.transferOwnership.selector;
        selectors[1] = handler.acceptOwnership.selector;

        targetSelector(FuzzSelector(address(handler), selectors));
    }

    function invariant_record_metrics() public view {
        assertEq(owned.owner(), owner);
    }
}
