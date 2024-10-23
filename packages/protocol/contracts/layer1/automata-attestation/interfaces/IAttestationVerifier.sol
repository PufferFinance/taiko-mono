//SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IAttestationVerifier
interface IAttestationVerifier {
    function verifyAttestation(bytes calldata _report, bytes32 _userData) external;
}
