// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../../../contracts/shared/common/LibStrings.sol";
import "../../../contracts/layer1/tiers/ITierProvider.sol";
import "../../../contracts/layer1/tiers/LibTiers.sol";
import "../../../contracts/layer1/tiers/ITierRouter.sol";

/// @title TestnetTierProvider
/// @dev Labeled in AddressResolver as "tier_router"
contract TestnetTierProvider is ITierProvider, ITierRouter {
    uint256[50] private __gap;

    /// @inheritdoc ITierRouter
    function getProvider(uint256) external view returns (address) {
        return address(this);
    }

    /// @inheritdoc ITierProvider

    function getTier(uint16 _tierId) public pure override returns (ITierProvider.Tier memory) {
        return ITierProvider.Tier({
            verifierName: "",
            validityBond: 250 ether, // TKO
            contestBond: 500 ether, // TKO
            cooldownWindow: 1, //1 minute
            provingWindow: 30, // 0.5 hours
            maxBlocksToVerifyPerProof: 0
        });
    }

    /// @inheritdoc ITierProvider
    function getTierIds() public pure override returns (uint16[] memory tiers_) {
        tiers_ = new uint16[](1);
        tiers_[0] = LibTiers.TIER_OPTIMISTIC;
    }

    /// @inheritdoc ITierProvider
    function getMinTier(address, uint256 _rand) public pure override returns (uint16) {
        return LibTiers.TIER_OPTIMISTIC;
    }
}
