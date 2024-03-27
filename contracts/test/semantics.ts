// SPDX-License-Identifier: Apache-2.0

import { ethers } from 'hardhat';
import { expect } from 'chai';
import { SemanticTests } from '../typechain-types/contracts/tests/SemanticTests';
import { ErrorFragment, Interface, getBytes } from 'ethers';

const ERROR_NUM =
  '0x1023456789abcdef1023456789abcdef1023456789abcdef1023456789abcdef';

describe('EVM Semantics', () => {
  let c: SemanticTests;
  let chainId: bigint;

  before(async () => {
    const f = await ethers.getContractFactory('SemanticTests');
    c = (await f.deploy()) as unknown as SemanticTests;
    await c.waitForDeployment();
    chainId = (await ethers.provider.getNetwork()).chainId;
  });

  it('eth_call constructor with custom error', async () => {
    const f = await ethers.getContractFactory('CreateFailCustom');
    const tx = await f.getDeployTransaction();
    const p = ethers.provider;
    let caught = false;
    try {
      const r = await p.call({
        data: tx.data,
        gasPrice: tx.gasPrice,
        gasLimit: tx.gasLimit,
      });
    } catch (x: any) {
      // XXX: typechain doesn't fully support custom errors from constructor
      const abi = {
        inputs: [
          {
            internalType: 'uint256',
            name: 'value',
            type: 'uint256',
          },
        ],
        name: 'CustomError',
        type: 'error',
      };
      const ef = ErrorFragment.from(abi);
      const iface = Interface.from([ef]);
      const expected = iface.encodeErrorResult(ef, [ERROR_NUM]);
      expect(x.info.error.data).eq(expected);
      caught = true;
    }
    expect(caught).eq(true);
  });

  it('eth_call constructor with require errror', async () => {
    const f = await ethers.getContractFactory('CreateFailRequire');
    const tx = await f.getDeployTransaction();
    const p = ethers.provider;
    let caught = false;
    try {
      await p.call({
        data: tx.data,
        gasPrice: tx.gasPrice,
        gasLimit: tx.gasLimit,
      });
    } catch (x: any) {
      expect(x.revert.args[0]).to.eq('ThisIsAnError');
      expect(x.revert.name).to.eq('Error');
      caught = true;
    }
    expect(caught).eq(true);
  });

  it('eth_call maximum return length vs gas limit', async () => {
    const i = 1211104;
    const respHex = await c.testViewLength(i);
    const respBytes = getBytes(respHex);
    expect(respBytes.length).eq(i);

    let caught = false;
    try {
      await c.testViewLength(i + 1);
    } catch (e: any) {
      caught = true;
      expect(e.info.error.message).contains('out of gas');
    }
    expect(caught).eq(true);
  });

  it('Error string in view call', async () => {
    try {
      await c.testViewRevert();
    } catch (x: any) {
      expect(x.revert.args[0]).to.eq('ThisIsAnError');
      expect(x.revert.name).to.eq('Error');
    }
  });

  it('Custom revert in view call', async () => {
    // Perform view call, which is expected to revert
    try {
      await c.testCustomViewRevert();
      expect(false).to.be.true;
    } catch (x: any) {
      expect(x.revert.args[0]).to.eq(ERROR_NUM);
      expect(x.revert.name).to.eq('CustomError');
    }
  });
});
