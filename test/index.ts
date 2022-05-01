import { ethers } from "hardhat";
import { expect } from "chai";
import { SignerWithAddress } from "@nomiclabs/hardhat-ethers/signers";
import { MynaWallet, TestToken } from "../typechain";
const mynaPubkeyExp = "010001";
const mynaPubkeyMod =
  "C2E48C45C07363E246BE44407C8AF5317CBCCD3AA8BE5D26129224525AC9FD73BC65296102D48744600952F0493C397657C966E2564FF9EF5175357EEC9628036096326107A90BD538F67390AAECBCD85672BDC66F088B3F1FA0657009C146DBEC38111C50757358E3016803CF5ECE665927B377AFDF058432A624B372D2E39CF534AB9ED449DA12BA239FE0DD96F65C72CCEA6B6BFD9733C41E90EDEE1F842078AC5CDE7C95C6242A322516EF22927F35ABB8AFE8327633D7DED0959384D205853B84726FABED29182F0213B6A74F118651D2C4C415B8253D3AC2D339C8775361B6201849FE99626F591F558C5C916A79182C856BB1599AD12BE5D33748E799";

export function toZeroX(x: string) {
  return "0x" + x;
}
export function mutateOneChar(str: string, index: number, char: string) {
  return str.substr(0, index) + char + str.substr(index + 1);
}

describe("MynaWallet", () => {
  it("should be able to create a wallet", async () => {
    const Wallet = await ethers.getContractFactory("MynaWallet");
    const wallet = await Wallet.deploy({
      e: toZeroX(mynaPubkeyExp),
      n: toZeroX(mynaPubkeyMod),
    });
    await wallet.deployed();

    const pubkey = await wallet.publicKey();

    expect(pubkey.e.toString()).to.equal(toZeroX(mynaPubkeyExp));
  });
});

describe("MynaWallet(ERC20)", () => {
  let testToken: TestToken;
  let wallet: MynaWallet;
  let spender: SignerWithAddress;
  beforeEach(async () => {
    const Test = await ethers.getContractFactory("TestToken");
    testToken = await Test.deploy();
    await testToken.deployed();

    const Wallet = await ethers.getContractFactory("MynaWallet");
    wallet = await Wallet.deploy({
      e: toZeroX(mynaPubkeyExp),
      n: toZeroX(mynaPubkeyMod),
    });
    await wallet.deployed();

    const signers = await ethers.getSigners();
    spender = signers[0];
  });

  it("should execute transaction", async () => {
    let allowance = await testToken.allowance(wallet.address, spender.address);

    expect(allowance.toNumber()).to.equal(0);
    const req = {
      target: testToken.address,
      value: ethers.utils.parseEther("0"),
      data: "0x",
      nonce: "0xdeadbeef",
    };
    const domain = {
      name: "MynaWallet",
      version: "1.0.0",
      chainId: await spender.getChainId(),
      verifyingContract: wallet.address,
    };
    const types = {
      ForwardRequest: [
        { name: "target", type: "address" },
        { name: "value", type: "uint256" },
        { name: "nonce", type: "bytes32" },
        { name: "data", type: "bytes" },
      ],
    };
    const sig = await spender._signTypedData(domain, types, req);
    await wallet.invoke(req, sig);

    allowance = await testToken.allowance(wallet.address, testToken.address);

    expect(allowance.toNumber()).to.equal(2);
  });
});
