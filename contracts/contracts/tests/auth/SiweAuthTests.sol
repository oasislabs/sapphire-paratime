// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

import {EthereumUtils, SignatureRSV} from "../../EthereumUtils.sol";
import {SiweAuth} from "../../auth/SiweAuth.sol";

contract SiweAuthTests is SiweAuth {
    address private _owner;

    constructor(string memory domain) SiweAuth(domain) {
        _owner = msg.sender;
    }

    function testVerySecretMessage(bytes calldata token)
        external
        view
        returns (string memory)
    {
        if (authMsgSender(token) != _owner) {
            revert("not allowed");
        }
        return "Very secret message";
    }

    function testLogin(string calldata message, SignatureRSV calldata sig)
        external
        view
        returns (bytes memory)
    {
        return this.login(message, sig);
    }

    function testAuthMsgSender(bytes calldata token)
        external
        view
        returns (address)
    {
        return authMsgSender(token);
    }

    function testRevokeAuthToken(bytes32 token) external {
        return revokeAuthToken(token);
    }

    function doNothing() external { // solhint-disable-line
        // Does nothing
    }
}
