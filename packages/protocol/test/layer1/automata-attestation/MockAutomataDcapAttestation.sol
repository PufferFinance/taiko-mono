//SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { IAttestationV2 } from
    "../../../contracts/layer1/automata-attestation/interfaces/IAttestationV2.sol";

/// @title MockAutomataDcapAttestation
contract MockAutomataDcapAttestation is IAttestationV2 {
    error FUNC_NOT_IMPLEMENTED();

    function verifyAndAttestOnChain(bytes calldata input)
        external
        returns (bool success, bytes memory output)
    {
        return (true, input);
    }

    function verifyAndAttestWithZKProof(
        bytes calldata journal,
        bytes calldata seal
    )
        external
        returns (bool success, bytes memory output)
    {
        revert FUNC_NOT_IMPLEMENTED();
    }
}
