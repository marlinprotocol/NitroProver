// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {NitroProver} from "../src/NitroProver.sol";

contract NitroProverScript is Script {
    NitroProver nitroProver;
    bytes attestation_doc;
    bytes pcrs;

    function setUp() public {
        uint256 deployerPrivKey = vm.envUint("ARB_SEPOLIA_KEY");

        vm.broadcast(deployerPrivKey);
        nitroProver = new NitroProver();

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
    }

    function run() public {
        uint256 deployerPrivKey = vm.envUint("ARB_SEPOLIA_KEY");
        vm.broadcast(deployerPrivKey);
        console.logBytes(attestation_doc);
        console.logBytes(pcrs);
        console.log(365 days);
        nitroProver.verifyAttestation{gas: 254805674}(attestation_doc, pcrs, 365 days);
    }
}
