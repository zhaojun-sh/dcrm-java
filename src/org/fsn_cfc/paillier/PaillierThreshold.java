package org.fsn_cfc.paillier;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;


public class PaillierThreshold extends Paillier{

	//distributed decrypted paillier private key
	private List<BigInteger> dPrivKeyList = null;

	
	public PaillierThreshold(PaPublicKey pubkey) {
		this.publicKey = pubkey;
	}
	
	
	public PaillierThreshold(PaPrivateKey prikey) {
		this(prikey.getPublicKey());
		this.privateKey = prikey;
	}


	public BigInteger decryptThreshold(BigInteger c, int userIndex, int userCnt)
	{

		//manually split the distributed paillier private key
		if(dPrivKeyList == null){
			BigInteger privKey = this.privateKey.getD();
			dPrivKeyList = manuallySplitPrivKey(privKey, userCnt);
		}

		BigInteger curPrivKey = dPrivKeyList.get(userIndex);

		return c.modPow(curPrivKey, this.publicKey.getNSPlusOne());

		//BigInteger msgTem2 = c1.multiply(c2).mod(nSPlusOne).subtract(BigInteger.ONE).divide(n);
	}


	private List<BigInteger> manuallySplitPrivKey(BigInteger privKey, int userCnt){

		List<BigInteger> dPrivKeyList =  new ArrayList<BigInteger>();

		int privKeyLen = privKey.bitLength();
		int dPrivKeyLen = privKeyLen / userCnt;

		BigInteger tem;
		BigInteger sum =  BigInteger.ZERO;
		for(int i = 0 ; i < userCnt - 1 ; i ++){
			tem =  new BigInteger(dPrivKeyLen, this.publicKey.getRnd());
			sum.add(tem);
			dPrivKeyList.add(tem);
		}

		tem = privKey.subtract(sum);
		dPrivKeyList.add(tem);

		return dPrivKeyList;
	}

	
}

