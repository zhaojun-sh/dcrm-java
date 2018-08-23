package org.fsn_cfc.paillier;

import java.math.BigInteger;

public class PaPrivateKeyThreshold extends PaPrivateKey {

	
	public PaPrivateKeyThreshold(BigInteger n, BigInteger d, long seed){
		super(n, d, seed);
	}
	
}
