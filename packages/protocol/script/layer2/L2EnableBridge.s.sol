// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/src/console2.sol";
import "forge-std/src/Script.sol";

import "../../contracts/shared/common/AddressManager.sol";
import "../../contracts/shared/common/LibStrings.sol";
import "../../contracts/shared/bridge/Bridge.sol";
import "../../contracts/shared/signal/SignalService.sol";

contract L2EnableBridge is Script {

    uint256 public privateKey = vm.envUint("L2_BRIDGE_OWNER_PK");
    address public l1Bridge = vm.envAddress("L1_BRIDGE");
    address public l2Bridge = vm.envAddress("L2_BRIDGE");
    address public l1Service = vm.envAddress("L1_SIGNAL_SERVICE_ADDRESS");

    modifier broadcast() {
        require(privateKey != 0, "invalid priv key");
        vm.startBroadcast();
        _;
        vm.stopBroadcast();
    }

    function run() external broadcast {
        Bridge bridge = Bridge(l2Bridge); // L2 bridge

        AddressManager addressManager = AddressManager(bridge.addressManager());

        SignalService signalService = SignalService(
            addressManager.getAddress(uint64(block.chainid), LibStrings.B_SIGNAL_SERVICE));
        console.log(address(signalService));

        console2.log(signalService.topBlockId(3151908, LibStrings.H_STATE_ROOT));
        address add = addressManager.getAddress(3151908, LibStrings.B_BRIDGE);
        if (add == address(0)) {
            console2.log("> setting bridge chain");
            addressManager.setAddress(3151908, LibStrings.B_BRIDGE, l1Bridge);
        }
        console.log(addressManager.getAddress(3151908, LibStrings.B_BRIDGE));

        address l1SignalService = addressManager.getAddress(3151908, LibStrings.B_SIGNAL_SERVICE);
        if (l1SignalService == address(0)) {
            addressManager.setAddress(3151908, LibStrings.B_SIGNAL_SERVICE, l1Service); // L1 signal service
        }
        console2.log(addressManager.getAddress(3151908, LibStrings.B_SIGNAL_SERVICE));
    }
}
