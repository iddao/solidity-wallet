//SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;
import "./RSAVerifier.sol";
import "./EIP712RSA.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/interfaces/IERC1271.sol";

contract MynaWallet is EIP712RSA, IERC1271 {
    /**
     * RSA Public Key
     */
    struct PublicKey {
        /** modulus */
        bytes n;
        /** exponent */
        bytes e;
    }

    PublicKey public publicKey;

    /**
     * @dev used/unused nonces pool
     * if true, the nonce is used
     */
    mapping(bytes32 => bool) nonces;

    /**
     * @dev locks for initalization phase
     */
    address factory;

    constructor() EIP712RSA("MynaWallet", "1.0.0") {
        factory = msg.sender;
    }

    /**
     * @dev initialize wallet
     * @param _pubkey public key
     */
    function initialize(PublicKey calldata _pubkey) public {
        require(msg.sender == factory, "Only factory can initialize wallet");
        publicKey = _pubkey;
        factory = address(0);
    }

    struct InvokeRequest {
        address target;
        uint256 value;
        bytes32 nonce;
        bytes data;
    }

    // keccak256("Invoke(address target,uint256 value,bytes32 nonce,bytes data)")
    bytes32 public constant INVOKE_TYPEHASH =
        0x25ed6deeffe2c81975d866495788e36da81797d1678431eb48c945d107f3f031;

    function invoke(InvokeRequest calldata req, bytes calldata signature)
        public
        returns (bytes memory _result)
    {
        bytes memory msgHash = getTypedData(
            keccak256(
                abi.encode(
                    INVOKE_TYPEHASH,
                    req.target,
                    req.value,
                    req.nonce,
                    req.data
                )
            )
        );

        require(
            RSAVerifier.verifySignature(
                publicKey.n,
                publicKey.e,
                sha256(msgHash),
                signature
            ),
            "Invalid signature"
        );

        require(!nonces[req.nonce], "Nonce already used");

        bool success;
        (success, _result) = req.target.call{value: req.value}(req.data);
        if (!success) {
            assembly {
                returndatacopy(0, 0, returndatasize())
                revert(0, returndatasize())
            }
        }
    }

    function isValidSignature(bytes32 hash, bytes calldata signature)
        external
        view
        override
        returns (bytes4 magicValue)
    {
        bool valid = RSAVerifier.verifySignature(
            publicKey.n,
            publicKey.e,
            hash,
            signature
        );
        if (valid) {
            magicValue = 0x1626ba7e;
        } else {
            magicValue = 0xffffffff;
        }
    }
}
