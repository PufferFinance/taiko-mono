// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/src/console2.sol";
import "forge-std/src/Script.sol";

import "../../contracts/shared/common/AddressManager.sol";
import "../../contracts/shared/common/LibStrings.sol";
import "../../contracts/shared/bridge/Bridge.sol";
import "../../contracts/shared/signal/SignalService.sol";

contract L1EnableBridge is Script {
    uint256 public privateKey = vm.envUint("PRIVATE_KEY");
    address public l1Bridge = vm.envAddress("L1_BRIDGE");
    address public l2Bridge = vm.envAddress("L2_BRIDGE");
    address public l2SignalService = vm.envAddress("L2_SIGNAL_SERVICE");


    modifier broadcast() {
        require(privateKey != 0, "invalid private key");
        vm.startBroadcast();
        _;
        vm.stopBroadcast();
    }

    function run() external broadcast {
        Bridge bridge = Bridge(l1Bridge); // L1 bridge

        AddressManager addressManager = AddressManager(bridge.addressManager());

        SignalService signalService = SignalService(
            addressManager.getAddress(uint64(block.chainid), LibStrings.B_SIGNAL_SERVICE));
        console.log(address(signalService));

        console2.log(signalService.topBlockId(167_200, LibStrings.H_STATE_ROOT));

        address add = addressManager.getAddress(167_200, LibStrings.B_BRIDGE);
        if (add == address(0)) {
            console2.log("> setting bridge chain");
            addressManager.setAddress(167_200, LibStrings.B_BRIDGE, l2Bridge);
        }

        address l2SignalServiceSet = addressManager.getAddress(167_200, LibStrings.B_SIGNAL_SERVICE);
        console2.log(address(l2SignalServiceSet));
        if (l2SignalServiceSet == address(0)) {
            addressManager.setAddress(167_200, LibStrings.B_SIGNAL_SERVICE, l2SignalService); // L2 signal service
        }
        console2.log(addressManager.getAddress(167_200, LibStrings.B_SIGNAL_SERVICE));
    }
}
