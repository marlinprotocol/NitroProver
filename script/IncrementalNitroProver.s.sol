// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {NitroProver} from "../src/NitroProver.sol";
import { CBORDecoding } from "marlinprotocol/solidity-cbor/CBORDecoding.sol";

contract NitroProverScript is Script {
    NitroProver nitroProver;
    bytes attestation_doc;
    bytes pcrs;
    bytes[5] certs;

    function setUp() public {
        uint256 deployerPrivKey = vm.envUint("ARB_SEPOLIA_KEY");

        vm.broadcast(deployerPrivKey);
        nitroProver = new NitroProver();

        console.log(address(nitroProver));

        // curl -v 13.201.207.60:1300 -o attestation.bin
        attestation_doc = vm.readFileBinary("./script/attestation.bin");
        pcrs = abi.encodePacked(
            hex"00000017", // pcr index starting from LSB. This represents PCR0,PCR1,PCR2,PCR4
            hex"189038eccf28a3a098949e402f3b3d86a876f4915c5b02d546abb5d8c507ceb1755b8192d8cfca66e8f226160ca4c7a6", 
            hex"5d3938eb05288e20a981038b1861062ff4174884968a39aee5982b312894e60561883576cc7381d1a7d05b809936bd16", 
            hex"6c3ef363c488a9a86faa63a44653fd806e645d4540b40540876f3b811fc1bceecf036a4703f07587c501ee45bb56a1aa",
            hex"45ff8769d16a46d16fcf4b872b546b02d587267a16d2325fb968453c0e36e243d04389e45466191967ceb1978012a9cf"
        );
        bytes memory payload = CBORDecoding.decodeArray(attestation_doc)[2];
        bytes memory certificate = CBORDecoding.decodeMappingGetValue(payload, bytes("certificate"));
        bytes[] memory cabundle = CBORDecoding.decodeArray(CBORDecoding.decodeMappingGetValue(payload, bytes("cabundle")));
        certs[0] = cabundle[0];
        certs[1] = cabundle[1];
        certs[2] = cabundle[2];
        certs[3] = cabundle[3];
        certs[4] = certificate;
    }

    function run() public {
        uint256 deployerPrivKey = vm.envUint("ARB_SEPOLIA_KEY");
        bytes32 parentCertHash = keccak256(certs[0]);
        for(uint256 i = 1; i < certs.length; i++) {
            bytes32 certHash = keccak256(certs[i]);
            if(nitroProver.certPubKey(certHash).length == 0) {
                vm.broadcast(deployerPrivKey);
                nitroProver.verifyCert(certs[i], parentCertHash);
            }
            parentCertHash = certHash;
        }
        vm.broadcast(deployerPrivKey);
        nitroProver.verifyAttestation(attestation_doc, pcrs, 365 days);
    }
}
