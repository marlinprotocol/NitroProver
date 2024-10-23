// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {CertManager} from "../src/CertManager.sol";
import {NitroProver} from "../src/NitroProver.sol";
import { CBORDecoding } from "marlinprotocol/solidity-cbor/CBORDecoding.sol";

contract NitroProverScript is Script {
    CertManager certManager;
    NitroProver nitroProver;
    bytes attestation_doc;
    bytes pcrs;
    bytes[5] certs;

    function setUp() public {
        uint256 deployerPrivKey = vm.envUint("ARB_SEPOLIA_KEY");

        vm.broadcast(deployerPrivKey);
        certManager = new CertManager();
        nitroProver = new NitroProver(certManager);

        console.log(address(nitroProver));

        // curl -v 13.200.82.143:1300 -o attestation.bin
        attestation_doc = vm.readFileBinary("./script/attestation.bin");
        pcrs = abi.encodePacked(
            hex"00000017", // pcr index starting from LSB. This represents PCR0,PCR1,PCR2,PCR4
            hex"ea6ff0cc81650a6a2e5e6b009b058d684600ea08006beafb60a693e2eeb362e3a06039ff8341f0715543672c5c9ffa61", 
            hex"41245c1ef3514f08230e85fd21d97dee1eb2c3cfbca59cabd15b8858bc45c019acbbf1ec737cec472ffd0b0d8040e4ba", 
            hex"861ca1d00bed2c7d8fa0bf5aa11fcb6a002fe729f3123477d470299fc5eb72ae886d33c3d73216064f9dc15e3f7251e2",
            hex"4f646fa18676065e77ed5b03b51755e30cf9ce450c2f6ae58b0e31e6308d58f576ea295d8579c1bf27db1de8fda9dd9a"
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
            if(certManager.certPubKey(certHash).length == 0) {
                vm.broadcast(deployerPrivKey);
                certManager.verifyCert(certs[i], parentCertHash);
            }
            parentCertHash = certHash;
        }
        vm.broadcast(deployerPrivKey);
        nitroProver.verifyAttestation(attestation_doc, pcrs, 365 days);
    }
}
