// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/src/Script.sol";
//import "../../contracts/layer1/token/TaikoToken.sol";
import "../../contracts/shared/bridge/Bridge.sol";
import "../../contracts/shared/bridge/IBridge.sol";
import "../../contracts/shared/common/AddressManager.sol";

contract EnableBridge is Script {
    uint256 public privateKey = vm.envUint("PRIVATE_KEY");
    address public l1Bridge = vm.envAddress("L1_BRIDGE");
    address public l2Bridge = vm.envAddress("L2_BRIDGE");

    modifier broadcast() {
        require(privateKey != 0, "invalid private key");
        vm.startBroadcast();
        _;
        vm.stopBroadcast();
    }

    function run() external broadcast {
        Bridge bridge = Bridge(l1Bridge); // L1 "Bridge" contract's proxy, `run-latest.json`

        (bool enabled, ) = bridge.isDestChainEnabled(167200);

        if (!enabled) {
            AddressManager addr_manager = AddressManager(bridge.addressManager());
            addr_manager.setAddress(167200, LibStrings.B_BRIDGE, l2Bridge); // L2 "Bridge" contract, `unifi_l2.json`
        }
    }
}