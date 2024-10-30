//SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "../../shared/common/EssentialContract.sol";
import "./interfaces/IAttestationV2.sol";
import "./interfaces/IAttestationVerifier.sol";

/// @title AttestationVerifier
contract AttestationVerifier is IAttestationVerifier, EssentialContract {
    IAttestationV2 public attestationVerifier; // slot 1

    uint256[49] private __gap;

    function init(
        address _owner,
        address _attestationVerifier
    )
        external
        initializer
    {
        __Essential_init(_owner);
        attestationVerifier = IAttestationV2(_attestationVerifier);
    }

    error INVALID_REPORT();
    error INVALID_REPORT_DATA();
    error REPORT_DATA_MISMATCH();

    function verifyAttestation(
        bytes calldata _report,
        bytes32 _userData
    ) 
        external
    {
        if (address(attestationVerifier) == address(0)) return;

        (bool succ, bytes memory output) = attestationVerifier
            .verifyAndAttestOnChain(_report);
        if (!succ) revert INVALID_REPORT();

        if (output.length < 32) revert INVALID_REPORT_DATA();

        bytes32 quoteBodyLast32;
        assembly {
            quoteBodyLast32 := mload(
                add(add(output, 0x20), sub(mload(output), 32))
            )
        }

        if (quoteBodyLast32 != _userData) revert REPORT_DATA_MISMATCH();
    }
}