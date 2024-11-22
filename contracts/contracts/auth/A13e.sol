// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

import {SignatureRSV} from "../EthereumUtils.sol";

/**
 * @title Interface for authenticatable contracts
 * @notice This is the interface for universal authentication mechanism (e.g.
 * SIWE):
 * 1. The user-facing app calls `login()` which generates the bearer token
 *    on-chain.
 * 2. Any smart contract method that requires authentication takes this token
 *    as an argument. It passes this token to `authMsgSender()` to verify it
 *    and obtain the **authenticated** user address. This address can then
 *    serve as a user ID for authorization.
 */
abstract contract A13e {
    /// A mapping of revoked bearers. Access it directly or use the checkRevokedBearer modifier.
    mapping(bytes32 => bool) internal _revokedBearers;

    /// The bearer token was revoked
    error RevokedBearer();

    /**
     * @notice Reverts if the given bearer was revoked
     */
    modifier checkRevokedBearer(bytes memory bearer) {
        if (_revokedBearers[keccak256(bearer)]) {
            revert RevokedBearer();
        }
        _;
    }

    /**
     * @notice Verify the login message and its signature and generate the
     * bearer token.
     */
    function login(string calldata message, SignatureRSV calldata sig)
        external
        view
        virtual
        returns (bytes memory);

    /**
     * @notice Validate the bearer token and return authenticated msg.sender.
     */
    function authMsgSender(bytes memory bearer)
        internal
        view
        virtual
        returns (address);

    /**
     * @notice Revoke the bearer token with the corresponding hash.
     * e.g. In case when the bearer token is leaked or for extra-secure apps on
     * every logout.
     */
    function revokeBearer(bytes32 bearer) internal {
        _revokedBearers[bearer] = true;
    }
}
