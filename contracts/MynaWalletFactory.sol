//SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;
import "./MynaWallet.sol";

contract MynaWalletFactory {
    mapping(bytes32 => address) public mynaWallets;

    event Created(address indexed mynaWallet);

    function createWallet(MynaWallet.PublicKey calldata _pubkey)
        public
        returns (address walletAddr)
    {
        bytes32 salt = getSalt(_pubkey);
        require(mynaWallets[salt] == address(0), "Wallet already exists");
        MynaWallet wallet = new MynaWallet{salt: salt}();
        wallet.initialize(_pubkey);

        walletAddr = address(wallet);

        mynaWallets[salt] = walletAddr;

        emit Created(walletAddr);
    }

    function computeWalletAddress(MynaWallet.PublicKey calldata _pubkey)
        public
        view
        returns (address walletAddr)
    {
        bytes memory initCode = type(MynaWallet).creationCode;

        bytes32 hash = keccak256(
            abi.encodePacked(
                hex"ff",
                address(this),
                getSalt(_pubkey),
                keccak256(initCode)
            )
        );
        assembly {
            walletAddr := hash
        }
    }

    function getSalt(MynaWallet.PublicKey memory _pubkey)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encodePacked(_pubkey.n, _pubkey.e));
    }
}
