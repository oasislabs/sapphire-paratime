// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

import {SignatureRSV} from "../EthereumUtils.sol";

/**
 * @title Interface for authenticatable contracts
 * @notice This is the interface for universal authentication mechanism (e.g.
 * SIWE):
 * 1. The user-facing app calls `login()` which generates the authentication
 *    token on-chain.
 * 2. Any smart contract method that requires authentication can take this token
 *    as an argument. Passing this token to `authMsgSender()` to verifies it
 *    and returns the **authenticated** user address. This verified address can
 *    then serve as a user ID for authorization.
 */
abstract contract A13e {
    /// A mapping of revoked authentication tokens. Access it directly or use the checkRevokedAuthToken modifier.
    mapping(bytes32 => bool) internal _revokedAuthTokens;

    /// The authentication token was revoked
    error RevokedAuthToken();

    /**
     * @notice Reverts if the given token was revoked
     */
    modifier checkRevokedAuthToken(bytes memory token) {
        if (_revokedAuthTokens[keccak256(token)]) {
            revert RevokedAuthToken();
        }
        _;
    }

    /**
     * @notice Verify the login message and its signature and generate the
     * token.
     */
    function login(string calldata message, SignatureRSV calldata sig)
        external
        view
        virtual
        returns (bytes memory);

    /**
     * @notice Validate the token and return authenticated msg.sender.
     */
    function authMsgSender(bytes memory token)
        internal
        view
        virtual
        returns (address);

    /**
     * @notice Revoke the authentication token with the corresponding hash.
     * e.g. In case when the token is leaked or for extra-secure apps on
     * every logout.
     */
    function revokeAuthToken(bytes32 token) internal {
        _revokedAuthTokens[token] = true;
    }
}
