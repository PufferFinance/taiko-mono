// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @title IBaseDepositContract
interface IBaseDepositContract {
    function getRoot() external view returns (bytes32);
}
