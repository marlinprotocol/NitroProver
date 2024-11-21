// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { console2 } from "forge-std/console2.sol";
import "../CertManager.sol";

contract CertManagerMock is CertManager {
    function t_verifyCert(bytes memory certificate, bytes memory pubKey) view external {
        _verifyCert(certificate, pubKey);
    }

    function t_parseTbs(bytes memory certificate, uint256 ptr) view external {
        _parseTbs(certificate, ptr);
    }
}
