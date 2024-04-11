// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { console2 } from "forge-std/console2.sol";
import "../NitroProver.sol";

contract TestMock is NitroProver {
    constructor() NitroProver() {}

    function t_verifyAttestation(bytes memory attestation, bytes memory PCRs, uint256 max_age) external {
        verifyAttestation(attestation, PCRs, max_age);
    }

    function t_processAttestationDoc(bytes memory attestation_payload, bytes memory expected_PCRs, uint256 max_age) external {
        _processAttestationDoc(attestation_payload, expected_PCRs, max_age);
    }

    function t_processSignature(bytes memory sig, bytes memory pubKey, bytes memory payload) external {
        _processSignature(sig, pubKey, payload);
    }

    function t_validatePCRs(bytes[2][] memory pcrs, bytes memory expected_pcrs) external {
        _validatePCRs(pcrs, expected_pcrs);
    }

    function t_verifyCerts(bytes memory certificate, bytes memory rawCAbundle) external {
        _verifyCerts(certificate, rawCAbundle);
    }

    function t_verifyCert(bytes memory certificate, bytes memory pubKey) external {
        _verifyCert(certificate, pubKey);
    }

    function t_parseTbs(bytes memory certificate, uint256 ptr) external {
        _parseTbs(certificate, ptr);
    }
}