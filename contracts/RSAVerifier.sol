//SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

library RSAVerifier {
    /**
     * RFC 8017 - PKCS #1 v2.1 Appendix B.1.
     */
    bytes19 constant sha256DigestValue =
        0x3031300d060960864801650304020105000420;

    /**
     * copies mem[_src : _src+_len] to mem[_dst : _dst+_len]
     */
    function memcpy(
        uint256 _dest,
        uint256 _src,
        uint256 _len
    ) private pure {
        unchecked {
            // Copy word-length chunks while possible
            for (; _len >= 32; _len -= 32) {
                /// @solidity memory-safe-assembly
                assembly {
                    mstore(_dest, mload(_src))
                }
                _dest += 32;
                _src += 32;
            }
            // Copy remaining bytes
            uint256 mask = 256**(32 - _len) - 1;
            assembly {
                let srcpart := and(mload(_src), not(mask))
                let destpart := and(mload(_dest), mask)
                mstore(_dest, or(destpart, srcpart))
            }
        }
    }

    /**
     * Creates input argument buffer for BigModExp.
     */
    function createInput(
        bytes memory _s, // 256 bytes
        bytes memory _e, // 1 <= _e.length <= 256
        bytes memory _m // 256 bytes
    ) private pure returns (bytes memory) {
        require(
            _s.length == 256 &&
                _m.length == 256 &&
                _e.length <= 256 &&
                _e.length > 0
        );
        uint256 eLen = _e.length;
        uint256 inputLen = 32 * 3 + 256 * 2 + eLen; // three uint256 field, then two 256-byte buffers and an _e.length buffer
        uint256 sp; // pointer of _s
        uint256 ep; // pointer of _e
        uint256 mp; // pointer of _m
        uint256 inputPtr; // pointer of input memory buffer
        bytes memory input = new bytes(inputLen);

        /// @solidity memory-safe-assembly
        assembly {
            sp := add(_s, 0x20) // ignores the length field
            ep := add(_e, 0x20) // ignores the length field
            mp := add(_m, 0x20) // ignores the length field
            mstore(add(input, 0x20), 256) // input + 0x20 := uint256(256)
            mstore(add(input, 0x40), eLen) // input + 0x40 := uint256(_e.length)
            mstore(add(input, 0x60), 256) // input + 0x60 := uint256(256)
            inputPtr := add(input, 0x20) // ignores the length field
        }
        memcpy(inputPtr + 32 * 3, sp, 256); // mem[inputPtr + 32 * 3 : inputPtr + 32 * 3 + 256] := mem[sp : sp + 256]
        memcpy(inputPtr + 32 * 3 + 256, ep, eLen); // mem[inputPtr + 32 * 3 + 256 : inputPtr + 32 * 3 + 256 + eLen] := mem[ep : ep + eLen]
        memcpy(inputPtr + 32 * 3 + 256 + eLen, mp, 256); // mem[inputPtr + 32 * 3 + 256 + eLen : inputPtr + 32 * 3 + 256 * 2 + eLen] := mem[mp : mp + 256]
        return input;
    }

    /**
     * Computes the modular exponentiation of a number by a power of two.
     *
     * @param _s the number to be exponentiated
     * @param _e the exponent
     * @param _m the modulus
     * @return ans the result of the modular exponentiation
     */
    function bigModExp(
        bytes memory _s, // 256-byte buffer
        bytes memory _e, // 1 <= _e.length <= 256
        bytes memory _m // 256-byte buffer
    ) private view returns (bytes memory) {
        bytes memory input = createInput(_s, _e, _m);
        uint256 inputlen = 32 * 3 + 256 * 3;
        bytes memory ans = new bytes(256); // 256-byte buffer for return value

        /// @solidity memory-safe-assembly
        assembly {
            let success := staticcall(
                sub(gas(), 2000), // gas cost
                5, // bigModExp precompiled contract address = 0x5
                add(input, 0x20), // ignores the length field
                inputlen, // input length
                add(ans, 0x20), // ignores the length field
                256
            )
            switch success
            case 0 {
                revert(0x0, 0x0)
            }
            default {
                // do nothing
            }
        }
        return ans;
    }

    function checkPaddedString(bytes memory encoded, bytes32 msgHash)
        private
        pure
        returns (bool)
    {
        // If emLen < tLen + 11, output "intended encoded message length too short"
        if (encoded.length < 32 + sha256DigestValue.length + 11) {
            return false;
        }
        uint256 paddingLen = encoded.length - 3 - sha256DigestValue.length - 32;
        if (
            encoded[0] != 0x00 ||
            encoded[1] != 0x01 ||
            encoded[paddingLen + 2] != 0x00
        ) {
            return false;
        }
        for (uint256 i = 0; i < paddingLen; i++) {
            if (encoded[i + 2] != 0xff) {
                return false;
            }
        }
        for (uint256 i = 0; i < sha256DigestValue.length; i++) {
            if (encoded[paddingLen + 3 + i] != sha256DigestValue[i]) {
                return false;
            }
        }
        for (uint256 i = 0; i < 32; i++) {
            if (
                encoded[paddingLen + 3 + sha256DigestValue.length + i] !=
                msgHash[i]
            ) {
                return false;
            }
        }
        return true;
    }

    /**
     * Verifies signature of RSA message.
     *
     * Algorithm spec:
     * - RSA Key size is 2048 bits.
     * - RSASSA-PKCS1-v1_5
     * - sha256WithRSAEncryption
     * - msgHash must be hashed with SHA256, size is 32 bytes
     * - signature must be 256 bytes
     */
    function verifySignature(
        bytes memory _modulus, // 256 bytes
        bytes memory _exponent, // 1 <= _e.length <= 256
        bytes32 _msgHash, // SHA256 hash of message
        bytes memory _signature // 256 bytes
    ) internal view returns (bool) {
        bytes memory plaintext = bigModExp(_signature, _exponent, _modulus);
        if (!checkPaddedString(plaintext, _msgHash)) {
            return false;
        }
        return true;
    }
}
