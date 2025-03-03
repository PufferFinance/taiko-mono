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
        if (_tierId == LibTiers.TIER_TDX) {
            return ITierProvider.Tier({
                verifierName: LibStrings.B_TIER_TDX,
                validityBond: 250 ether, // TKO
                contestBond: 1640 ether, // =250TKO * 6.5625
                cooldownWindow: 1, // 1 minute
                provingWindow: 60, // 1 hours
                maxBlocksToVerifyPerProof: 0
            });
        }

        if (_tierId == LibTiers.TIER_GUARDIAN) {
            return ITierProvider.Tier({
                verifierName: LibStrings.B_TIER_GUARDIAN,
                validityBond: 0, // must be 0 for top tier
                contestBond: 0, // must be 0 for top tier
                cooldownWindow: 1, //1 minute
                provingWindow: 2880, // 48 hours
                maxBlocksToVerifyPerProof: 0
            });
        }

        revert TIER_NOT_FOUND();
    }

    /// @inheritdoc ITierProvider
    function getTierIds() public pure override returns (uint16[] memory tiers_) {
        tiers_ = new uint16[](3);
        tiers_[0] = LibTiers.TIER_TDX;
        tiers_[1] = LibTiers.TIER_GUARDIAN;
    }

    /// @inheritdoc ITierProvider
    function getMinTier(address, uint256 _rand) public pure override returns (uint16) {
        return LibTiers.TIER_TDX;
    }
}
