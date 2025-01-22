// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/src/console2.sol";
import "forge-std/src/Script.sol";

import "../../contracts/shared/common/AddressManager.sol";
import "../../contracts/shared/common/LibStrings.sol";
import "../../contracts/shared/bridge/Bridge.sol";
import "../../contracts/shared/signal/SignalService.sol";
import "../../contracts/layer1/based/TaikoL1.sol";
import "../../contracts/layer1/provers/GuardianProver.sol";
import "../../contracts/layer1/provers/ProverSet.sol";
import "../../contracts/layer1/token/TaikoToken.sol";


contract EnableProverSet is Script {
    modifier broadcast() {
        uint256 privateKey = vm.envUint("PRIVATE_KEY");
        require(privateKey != 0, "invalid priv key");
        vm.startBroadcast();
        _;
        vm.stopBroadcast();
    }

    function run() external broadcast {
        address payable proverSetAddress = payable(vm.envAddress("PROVER_SET"));
        address taikoTokenAddress = vm.envAddress("TAIKO_TOKEN_ADDRESS");
        address taikoL1Address = vm.envAddress("TAIKO_L1_ADDRESS");
        address proposer = vm.envAddress("PROPOSER_ADDRESS");
        address prover = vm.envAddress("PROVER_ADDRESS");

        ProverSet ps = ProverSet(proverSetAddress);
        TaikoToken taikoToken = TaikoToken(taikoTokenAddress);

        taikoToken.transfer(address(ps), 10_000_000 ether);
        ps.approveAllowance(taikoL1Address, 10_000_000 ether);
        ps.enableProver(proposer, true);
        ps.enableProver(prover, true);
    }
}
