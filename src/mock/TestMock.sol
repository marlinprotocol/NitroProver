// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { console2 } from "forge-std/console2.sol";
import "../NitroProver.sol";

contract TestMock is NitroProver {
    function t_verifyAttestation(bytes memory attestation, bytes memory PCRs, uint256 max_age) public {
        verifyAttestation(attestation, PCRs, max_age);
    }

    function t_processAttestationDoc(bytes memory attestation_payload, bytes memory expected_PCRs, uint256 max_age) public {
        _processAttestationDoc(attestation_payload, expected_PCRs, max_age);
    }

    function t_processSignature(bytes memory sig, bytes memory pubKey, bytes memory payload) public {
        _processSignature(sig, pubKey, payload);
    }

    function t_validatePCRs(bytes[2][] memory pcrs, bytes memory expected_pcrs) public {
        _validatePCRs(pcrs, expected_pcrs);
    }

    function t_verifyCerts(bytes memory certificate, bytes memory rawCAbundle) public {
        _verifyCerts(certificate, rawCAbundle);
    }

    function t_verifyCert(bytes memory certificate, bytes memory pubKey) public {
        _verifyCert(certificate, pubKey);
    }

    function t_parseTbs(bytes memory certificate, uint256 ptr) public {
        _parseTbs(certificate, ptr);
    }
}