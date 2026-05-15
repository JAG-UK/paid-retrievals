#!/usr/bin/env node
import { ethers } from "ethers";

const [rpcUrl, privateKey, tokenAddr, spender, inputAmount = "1000", decimals = "6"] = process.argv.slice(2);

const provider = new ethers.JsonRpcProvider(rpcUrl);
const signer = new ethers.Wallet(privateKey, provider);
const token = new ethers.Contract(tokenAddr, [
  "function nonces(address) view returns (uint256)",
  "function name() view returns (string)",
], signer);

const [nonce, name, network] = await Promise.all([
  token.nonces(signer.address),
  token.name(),
  provider.getNetwork(),
]);

const amount = ethers.parseUnits(inputAmount, Number(decimals));
const deadline = Math.floor(Date.now() / 1000) + 3600;

const sig = ethers.Signature.from(await signer.signTypedData(
  { name, version: "1", chainId: network.chainId, verifyingContract: tokenAddr },
  {
    Permit: [
      { name: "owner", type: "address" },
      { name: "spender", type: "address" },
      { name: "value", type: "uint256" },
      { name: "nonce", type: "uint256" },
      { name: "deadline", type: "uint256" },
    ]
  },
  { owner: signer.address, spender, value: BigInt(amount), nonce, deadline: BigInt(deadline) }
));

process.stdout.write(JSON.stringify({ v: sig.v, r: sig.r, s: sig.s, amount: amount.toString(), deadline: deadline.toString() }) + "\n");
