// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {CertManager} from "../src/CertManager.sol";
import {CertManagerMock} from "../src/mock/CertManagerMock.sol";

contract CertManagerTest is Test {
    CertManagerMock internal certManagerTest;

    function setUp() public {
        vm.warp(1708930774);
        certManagerTest = new CertManagerMock();
    }

    function test_verifyCert() public view {
        bytes memory certificate = hex"3082027e30820203a0030201020210018d1c7ef94eb1100000000065dc36d8300a06082a8648ce3d04030330818f310b30090603550406130255533113301106035504080c0a57617368696e67746f6e3110300e06035504070c0753656174746c65310f300d060355040a0c06416d617a6f6e310c300a060355040b0c03415753313a303806035504030c31692d30646632333766303431386665623431652e61702d736f7574682d312e6177732e6e6974726f2d656e636c61766573301e170d3234303232363036353933335a170d3234303232363039353933365a308194310b30090603550406130255533113301106035504080c0a57617368696e67746f6e3110300e06035504070c0753656174746c65310f300d060355040a0c06416d617a6f6e310c300a060355040b0c03415753313f303d06035504030c36692d30646632333766303431386665623431652d656e63303138643163376566393465623131302e61702d736f7574682d312e6177733076301006072a8648ce3d020106052b8104002203620004eb09f84282efd096cbe7964dbe67070bae5e8086bc1188f3f7cf79a6095d85898f61660bc9a5c0ad9a56a6141420c6eef5d74446d7124d944676c1d9cf2b3cd46dec6f13056c634b01d1b9fe309c222f34a56247ceb037a56b7adcd428f0df6aa31d301b300c0603551d130101ff04023000300b0603551d0f0404030206c0300a06082a8648ce3d0403030369003066023100fea3f5cfaf969d75e7b9583ce3313e994df0baee848f11f7be2fd1a7629f69b303ef73cd28cca11c207da137222a63c6023100d34de845696123850a2e379acc1968377e236d495c75ab10380fd93941cb4abf61bacb503027315471a58a12612943ff";
        bytes memory pubKey = hex"046baba8f1e9aa967fe7e3fa54b89138cc89dda5be11a1b52df080d94178e30105e76f08b75aa6caebefe8963366bb6dd0a22b33c6dc689a99448a0a16d2a7225e7d48941ee8f8b2b0523f77127dbfacc2866008a8bb9082b20a0f71a1e4eb0ede";
        certManagerTest.t_verifyCert(certificate, pubKey);
    }

    function test_parseTBS() public view {
        bytes memory certificate = hex"3082027e30820203a0030201020210018d1c7ef94eb1100000000065dc36d8300a06082a8648ce3d04030330818f310b30090603550406130255533113301106035504080c0a57617368696e67746f6e3110300e06035504070c0753656174746c65310f300d060355040a0c06416d617a6f6e310c300a060355040b0c03415753313a303806035504030c31692d30646632333766303431386665623431652e61702d736f7574682d312e6177732e6e6974726f2d656e636c61766573301e170d3234303232363036353933335a170d3234303232363039353933365a308194310b30090603550406130255533113301106035504080c0a57617368696e67746f6e3110300e06035504070c0753656174746c65310f300d060355040a0c06416d617a6f6e310c300a060355040b0c03415753313f303d06035504030c36692d30646632333766303431386665623431652d656e63303138643163376566393465623131302e61702d736f7574682d312e6177733076301006072a8648ce3d020106052b8104002203620004eb09f84282efd096cbe7964dbe67070bae5e8086bc1188f3f7cf79a6095d85898f61660bc9a5c0ad9a56a6141420c6eef5d74446d7124d944676c1d9cf2b3cd46dec6f13056c634b01d1b9fe309c222f34a56247ceb037a56b7adcd428f0df6aa31d301b300c0603551d130101ff04023000300b0603551d0f0404030206c0300a06082a8648ce3d0403030369003066023100fea3f5cfaf969d75e7b9583ce3313e994df0baee848f11f7be2fd1a7629f69b303ef73cd28cca11c207da137222a63c6023100d34de845696123850a2e379acc1968377e236d495c75ab10380fd93941cb4abf61bacb503027315471a58a12612943ff";
        uint256 ptr = 762903854686731323302323492349306293177430185082884;
        certManagerTest.t_parseTbs(certificate, ptr);
    }
}