// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { console2 } from "forge-std/console2.sol";

import { ECDSA384 } from "dl-solarity/solidity-lib/libs/crypto/ECDSA384.sol";
import { Sha2Ext } from "marlinprotocol/SolSha2Ext/Sha2Ext.sol";
import { LibBytes } from "marlinprotocol/SolSha2Ext/LibBytes.sol";
import { CBORDecoding } from "marlinprotocol/solidity-cbor/CBORDecoding.sol";
import { CBOR } from "marlinprotocol/solidity-cbor/CBOREncoding.sol";
import { ByteParser } from "marlinprotocol/solidity-cbor/ByteParser.sol";
import { Asn1Decode } from "./lib/Asn1Decode.sol";
import { DateTimeLibrary } from "./lib/DateTimeLibrary.sol";
import { BytesUtils } from "./lib/BytesUtils.sol";
import { CertManager } from "./CertManager.sol";

// @title NitroProver
// @notice Allows verification of AWS nitro attestations in Solidity
// @dev Implements verification based on AWS nitro attestation process at 
//      https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html and
//      https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/main/docs/attestation_process.md
contract NitroProver {
    using Asn1Decode for bytes;

    // @dev curve parameters for P384 as per section 3.2.1.4 of https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186.pdf
    // @dev lowSmax is the maximum value of s for a valid signature. It is half of the order of the curve.
    ECDSA384.Parameters public ECDSA384_PARAMS = ECDSA384.Parameters({
        a: bytes("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc"),
        b: bytes("0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef"),
        gx: bytes("0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7"),
        gy: bytes("0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f"),
        p: bytes("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff"),
        n: bytes("0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973"),
        lowSmax: bytes("0x7fffffffffffffffffffffffffffffffffffffffffffffffe3b1a6c0fa1b96efac0d06d9245853bd76760cb5666294b9")
    });

    CertManager public immutable certManager;

    constructor(CertManager _certManager) {
        certManager = _certManager;
    }

    function verifyCerts(bytes memory attestation) public {
        bytes[] memory attestation_decoded = CBORDecoding.decodeArray(attestation);
        bytes memory payload = attestation_decoded[2];
        bytes memory rawCAbundle = CBORDecoding.decodeMappingGetValue(payload, "cabundle");
        bytes memory certificate = CBORDecoding.decodeMappingGetValue(payload, "certificate");
        bytes[] memory cabundle = CBORDecoding.decodeArray(rawCAbundle);

        bytes32 parentCertHash;
        for(uint256 i=0; i < cabundle.length; i++) {
            bytes32 certHash = keccak256(cabundle[i]);
            if (certManager.certPubKey(certHash).length == 0) {
                certManager.verifyCert(cabundle[i], parentCertHash);
            }
            parentCertHash = certHash;
        }
        certManager.verifyCert(certificate, parentCertHash);
    }

    function verifyAttestation(bytes memory attestation, bytes memory PCRs, uint256 max_age) public view returns(bytes memory, bytes memory) {
        (bytes memory enclaveKey, bytes memory userData, bytes memory rawPcrs) =
            verifyAttestation(attestation, max_age);
        bytes[2][] memory pcrs = CBORDecoding.decodeMapping(rawPcrs);
        validatePCRs(pcrs, PCRs);
        return (enclaveKey, userData);
    }

    function verifyAttestation(bytes memory attestation, uint256 max_age) public view returns(bytes memory, bytes memory, bytes memory) {
        /* 
        https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/main/docs/attestation_process.md#31-cose-and-cbor
        Attestation document is an array of 4 elements
        [
            protected:   Header,
            unprotected: Header,
            payload:     This field contains the serialized content to be signed,
            signature:   This field contains the computed signature value.
        ]
        */
        
        // GAS: Attestation decode gas ~62k
        bytes[] memory attestation_decoded = CBORDecoding.decodeArray(attestation);

        // TODO: confirm that the attestation is untagged CBOR structure
        // https://datatracker.ietf.org/doc/html/rfc8152#section-3.1
        // Protected header for COSE_Sign1
        bytes[2][] memory protected_header = CBORDecoding.decodeMapping(attestation_decoded[0]);
        // Protected header should have algorithm flag which is specified by 1
        require(ByteParser.bytesToUint64(protected_header[0][0]) == 1, "Not algo flag");
        // Algorithm should be ECDSA w/ SHA-384
        require(ByteParser.bytesToNegativeInt128(protected_header[0][1]) == -35, "Incorrect algorithm");
        // Protected header should just have sig algo flag
        require(protected_header.length == 1, "Only algo flag should be present");

        // Unprotected header for COSE_Sign1
        bytes[2][] memory unprotected_header = CBORDecoding.decodeMapping(attestation_decoded[1]);
        // Unprotected header should be empty
        require(unprotected_header.length == 0, "Unprotected header should be empty");

        bytes memory payload = attestation_decoded[2];
        (bytes memory pubKey, bytes memory enclaveKey, bytes memory userData, bytes memory rawPcrs) = _processAttestationDoc(payload, max_age);

        // verify COSE signature as per https://www.rfc-editor.org/rfc/rfc9052.html#section-4.4
        bytes memory attestationSig = attestation_decoded[3];

        // create COSE structure
        // GAS: COSE structure creation gas ~42.7k
        // TODO: set CBOR length appropriately
        CBOR.CBORBuffer memory buf = CBOR.create(payload.length*2);
        CBOR.startFixedArray(buf, 4);
        // context to be written as Signature1 as COSE_Sign1 is used https://www.rfc-editor.org/rfc/rfc9052.html#section-4.4-2.1.1
        CBOR.writeString(buf, "Signature1");
        // Protected headers to be added https://www.rfc-editor.org/rfc/rfc9052.html#section-4.4-2.2
        CBOR.writeBytes(buf, attestation_decoded[0]);
        // externally supplied data is empty https://www.rfc-editor.org/rfc/rfc9052.html#section-4.4-2.4
        CBOR.writeBytes(buf, "");
        // Payload to be added https://www.rfc-editor.org/rfc/rfc9052.html#section-4.4-2.5
        CBOR.writeBytes(buf, payload);

        _processSignature(attestationSig, pubKey, buf.buf.buf);
        return (enclaveKey, userData, rawPcrs);
    }

    function _processAttestationDoc(bytes memory attestation_payload, uint256 max_age) internal view returns(bytes memory, bytes memory, bytes memory, bytes memory) {
        // TODO: validate if this check is expected? https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/main/docs/attestation_process.md?plain=1#L168
        require(attestation_payload.length <= 2**15, "Attestation too long");

        // validations as per https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/main/docs/attestation_process.md#32-syntactical-validation
        // issuing Nitro hypervisor module ID
        // GAS: decoding takes ~173.5k gas
        bytes[2][] memory attestation_structure = CBORDecoding.decodeMapping(attestation_payload);
        bytes memory moduleId;
        bytes memory rawTimestamp;
        bytes memory digest;
        bytes memory rawPcrs;
        bytes memory certificate;
        bytes memory rawCAbundle;
        bytes memory enclave_pub_key;
        bytes memory userData;

        for(uint256 i=0; i < attestation_structure.length; i++) {
            bytes32 keyHash = keccak256(attestation_structure[i][0]);
            if(keyHash == keccak256(bytes("module_id"))) {
                moduleId = attestation_structure[i][1];
                continue;
            }
            if(keyHash == keccak256(bytes("timestamp"))) {
                rawTimestamp = attestation_structure[i][1];
                continue;
            }
            if(keyHash == keccak256(bytes("digest"))) {
                digest = attestation_structure[i][1];
                continue;
            }
            if(keyHash == keccak256(bytes("pcrs"))) {
                rawPcrs = attestation_structure[i][1];
                continue;
            }
            if(keyHash == keccak256(bytes("certificate"))) {
                certificate = attestation_structure[i][1];
                continue;
            }
            if(keyHash == keccak256(bytes("cabundle"))) {
                rawCAbundle = attestation_structure[i][1];
                continue;
            }
            if(keyHash == keccak256(bytes("public_key"))) {
                enclave_pub_key = attestation_structure[i][1];
                continue;
            }
            if(keyHash == keccak256(bytes("user_data"))) {
                userData = attestation_structure[i][1];
                continue;
            }
        }

        require(moduleId.length != 0, "Invalid module id");

        uint64 timestamp = ByteParser.bytesToUint64(rawTimestamp);
        require(timestamp != 0, "invalid timestamp");
        require(timestamp + max_age > block.timestamp, "attestation too old");

        require(bytes32(digest) == bytes32("SHA384"), "invalid digest algo");

        bytes[] memory cabundle = CBORDecoding.decodeArray(rawCAbundle);
        bytes memory pubKey = certManager.verifyCertBundle(certificate, cabundle);

        return (pubKey, enclave_pub_key, userData, rawPcrs);
    }

    function validatePCRs(bytes[2][] memory pcrs, bytes memory expected_pcrs) public pure {
        require(pcrs.length != 0, "no pcr specified");
        require(pcrs.length <= 32, "only 32 pcrs allowed");
        require(expected_pcrs.length >= 4, "pcrs to check invalid");
        // flags that represent PCR indices to check starts from LSB
        // expected_pcrs looks like PCR32Flag PCR31Flag PCR30Flag ...... PCR2Flag PCR1Flag PCR0Flag <list PCRs with flag enabled starting from PCR0>
        uint32 pcrsToCheck = uint32(bytes4(LibBytes.slice(expected_pcrs, 0, 4)));
        uint256 expected_pcrs_pointer = 4;
        for(uint256 i=0; i < pcrs.length; i++) {
            if(expected_pcrs_pointer >= expected_pcrs.length && pcrsToCheck == 0) break; // short circuit
            if(pcrsToCheck % 2 == 1) {
                bytes memory expected_pcr = LibBytes.slice(expected_pcrs, expected_pcrs_pointer, expected_pcrs_pointer += 48);
                // TODO: do not assume pcrs map is ordered
                require(uint8(bytes1(pcrs[i][0])) == uint8(i), "PCRs not orderd");
                require(keccak256(pcrs[i][1]) == keccak256(expected_pcr), "PCR not matching");
            }
            pcrsToCheck = pcrsToCheck >> 1;
        }
    }

    function _processSignature(bytes memory sig, bytes memory pubKey, bytes memory payload) internal view {
        // TODO: Why are 32 and 64 mentioned as possible lengths? https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/main/docs/attestation_process.md?plain=1#L169
        require(sig.length == 96, "signature too long");
        verifyES384WithSHA384(pubKey, payload, sig);
    }

    function verifyES384WithSHA384(bytes memory pk, bytes memory message, bytes memory sig) internal view {
        require(pk.length == 97, "invalid pub key length");
        require(sig.length == 96, "invalid sig length");
        (bytes16 mhi, bytes32 mlo) = Sha2Ext.sha384(message);
        pk = LibBytes.slice(pk, 1, pk.length);
        require(ECDSA384.verify(ECDSA384_PARAMS, , sig, pk), "invalid sig");
    }
}
