// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";

import {SignatureRSV, A13e} from "./A13e.sol";
import {ParsedSiweMessage, SiweParser} from "../SiweParser.sol";
import {Sapphire} from "../Sapphire.sol";

struct Bearer {
    string domain; // [ scheme "://" ] domain.
    address userAddr;
    uint256 validUntil; // in Unix timestamp.
}

/**
 * @title Base contract for SIWE-based authentication
 * @notice Inherit this contract, if you wish to enable SIWE-based
 * authentication for your contract methods that require authentication.
 * The smart contract needs to be bound to a domain (passed in constructor).
 *
 * #### Example
 *
 * ```solidity
 * contract MyContract is SiweAuth {
 *   address private _owner;
 *   string private _message;
 *
 *   modifier onlyOwner(bytes calldata bearer) {
 *     if (msg.sender != _owner && authMsgSender(bearer) != _owner) {
 *       revert("not allowed");
 *     }
 *     _;
 *   }
 *
 *   constructor(string memory domain) SiweAuth(domain) {
 *     _owner = msg.sender;
 *   }
 *
 *   function getSecretMessage(bytes calldata bearer) external view onlyOwner(bearer) returns (string memory) {
 *     return _message;
 *   }
 *
 *   function setSecretMessage(string calldata message) external onlyOwner("") {
 *     _message = message;
 *   }
 * }
 * ```
 */
contract SiweAuth is A13e {
    /// Domain which the dApp is associated with
    string private _domain;
    /// Encryption key which the bearer tokens are encrypted with
    bytes32 private _bearerEncKey;
    /// Default bearer token validity, if no expiration-time provided
    uint256 private constant DEFAULT_VALIDITY = 24 hours;

    /// Chain ID in the SIWE message does not match the actual chain ID
    error ChainIdMismatch();
    /// Domain in the SIWE message does not match the domain of a dApp
    error DomainMismatch();
    /// User address in the SIWE message does not match the message signer's address
    error AddressMismatch();
    /// The Not before value in the SIWE message is still in the future
    error NotBeforeInFuture();
    /// The bearer token validity or the Expires value in the SIWE message is in the past
    error Expired();

    /**
     * @notice Instantiate the contract which uses SIWE for authentication and
     * runs on the specified domain.
     */
    constructor(string memory inDomain) {
        _bearerEncKey = bytes32(Sapphire.randomBytes(32, ""));
        _domain = inDomain;
    }

    function login(string calldata siweMsg, SignatureRSV calldata sig)
        external
        view
        override
        returns (bytes memory)
    {
        Bearer memory b;

        // Derive the user's address from the signature.
        bytes memory eip191msg = abi.encodePacked(
            "\x19Ethereum Signed Message:\n",
            Strings.toString(bytes(siweMsg).length),
            siweMsg
        );
        address addr = ecrecover(
            keccak256(eip191msg),
            uint8(sig.v),
            sig.r,
            sig.s
        );
        b.userAddr = addr;

        ParsedSiweMessage memory p = SiweParser.parseSiweMsg(bytes(siweMsg));

        if (p.chainId != block.chainid) {
            revert ChainIdMismatch();
        }

        if (keccak256(p.schemeDomain) != keccak256(bytes(_domain))) {
            revert DomainMismatch();
        }
        b.domain = string(p.schemeDomain);

        if (p.addr != addr) {
            revert AddressMismatch();
        }

        if (
            p.notBefore.length != 0 &&
            block.timestamp <= SiweParser.timestampFromIso(p.notBefore)
        ) {
            revert NotBeforeInFuture();
        }

        if (p.expirationTime.length != 0) {
            // Compute expected block number at expiration time.
            uint256 expirationTime = SiweParser.timestampFromIso(
                p.expirationTime
            );
            b.validUntil = expirationTime;
        } else {
            // Otherwise, just take the default validity.
            b.validUntil = block.timestamp + DEFAULT_VALIDITY;
        }
        if (block.timestamp >= b.validUntil) {
            revert Expired();
        }

        bytes memory encB = Sapphire.encrypt(
            _bearerEncKey,
            0,
            abi.encode(b),
            ""
        );
        return encB;
    }

    /**
     * @notice Return the domain associated with the dApp.
     */
    function domain() public view returns (string memory) {
        return _domain;
    }

    function authMsgSender(bytes memory bearer)
        internal
        view
        override
        checkRevokedBearer(bearer)
        returns (address)
    {
        if (bearer.length == 0) {
            return address(0);
        }
        bytes memory bearerEncoded = Sapphire.decrypt(
            _bearerEncKey,
            0,
            bearer,
            ""
        );
        Bearer memory b = abi.decode(bearerEncoded, (Bearer));

        if (keccak256(bytes(b.domain)) != keccak256(bytes(_domain))) {
            revert DomainMismatch();
        }
        if (b.validUntil < block.timestamp) {
            revert Expired();
        }

        return b.userAddr;
    }
}
