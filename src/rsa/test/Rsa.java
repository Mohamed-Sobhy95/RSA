
package rsa.test;
/**
 *
 * @author mahmoud
 */
import java.math.*;
import java.util.Random;
public class Rsa {
    private static final BigInteger ZERO = BigInteger.ZERO;
    private static final BigInteger ONE = BigInteger.ONE;
    private static final BigInteger TWO = new BigInteger("2");
    private static final BigInteger THREE = new BigInteger("3");
    int m_iBitSize;
    public BigInteger P,Q,PhiN,d;
    public BigInteger n,e;
    Rsa(int iBitsize){
     m_iBitSize = iBitsize;
            if(true)
            {
//                P = BigInteger.probablePrime(m_iBitSize, new Random());//p
//                Q = BigInteger.probablePrime(m_iBitSize, new Random());//q
                Random rand = new Random();
                P =new BigInteger(m_iBitSize, rand);
                Q =new BigInteger(m_iBitSize, rand); 
                while(!isProbablePrime(P, 20)){
                    P =new BigInteger(m_iBitSize, rand);
                }
                while(!isProbablePrime(Q, 20)&&!Q.equals(P)){
                    Q =new BigInteger(m_iBitSize, rand);
                }
                
                
                
                n = P.multiply(Q);//n=pq
                PhiN = P.subtract(BigInteger.valueOf(1)).multiply(Q.subtract(BigInteger.valueOf(1)));//phi(n)=(p-1)(q-1)
                // Next choose e, coprime to and less than PhiN ,,1 < e < ϕ(n),gcd(e,ϕ(n))=1, e is Public Key
                do
                {
                    e = new BigInteger(2 * m_iBitSize, new Random());
                    if((e.compareTo(PhiN) == -1) && (e.compareTo(BigInteger.ONE) == 1) && (e.gcd(PhiN).compareTo(BigInteger.ONE) == 0))
                        break;
                } while (true);
                d = inverse(e,PhiN);//de ≡ 1 (mod ϕ(n)).
            }
            
        
    }

      
        public String encryptPlainStrToHex(String sPlainStr)
        {
            return encryptMessage(convertStringToHex(sPlainStr),n, d);
        }
        public String decryptHexCipherToPlainMsg(String sHexCipherMsg)
        {
            return convertHexToString(decryptMessage(sHexCipherMsg,n,e));
        }
        private String encryptMessage(String sHexString, BigInteger N, BigInteger e)
        {
            if(sHexString.length()==0 || sHexString == null)
                return null;
            int maxstrlength = m_iBitSize/2;
            if (maxstrlength <= sHexString.length())
            {
                String sRetOutStr = "";
                String sOutStr = null;
                int iBeginIndex = 0;
                int iEndIndex = maxstrlength - 1;
                while (iBeginIndex < sHexString.length())
                {
                    if (iEndIndex < sHexString.length()) {
                        //sOutStr = (new BigInteger(sHexString.substring(iBeginIndex, iEndIndex), 16)).modPow(e, N).toString(16);
                        sOutStr=ModPow(new BigInteger(sHexString.substring(iBeginIndex, iEndIndex), 16), e, N).toString(16);
                        iBeginIndex = iEndIndex;
                        iEndIndex += (maxstrlength - 1);
                    }
                    else
                    {
                        //sOutStr = (new BigInteger(sHexString.substring(iBeginIndex), 16)).modPow(e, N).toString(16);
                        sOutStr=ModPow(new BigInteger(sHexString.substring(iBeginIndex), 16), e, N).toString(16);
                        iBeginIndex = sHexString.length();
                    }
                    if(sOutStr.length() < maxstrlength)
                    {
                        int iLen = maxstrlength - sOutStr.length();
                        for(int k = 0;k < iLen;k++)
                            sOutStr = "0" + sOutStr;
                    }
                    sRetOutStr += sOutStr;
                }
                return sRetOutStr;
            }
            else
                //return (new BigInteger(sHexString, 16)).modPow(e, N).toString(16);
                return ModPow(new BigInteger(sHexString, 16), e, N).toString(16);
        }
        private String decryptMessage(String sHexString, BigInteger N, BigInteger d)
        {
            if(sHexString.length()==0 || sHexString == null)
                return null;
            int maxstrlength = m_iBitSize/2;
            if (maxstrlength < sHexString.length())
            {
                String sRetOutStr = "";
                int iBeginIndex = 0;
                int iEndIndex = maxstrlength;
                while (iBeginIndex < sHexString.length())
                {
                    if (iEndIndex < sHexString.length())
                    {
                       // sRetOutStr += (new BigInteger(sHexString.substring(iBeginIndex, iEndIndex), 16)).modPow(d, N).toString(16);
                        sRetOutStr += ModPow(new BigInteger(sHexString.substring(iBeginIndex, iEndIndex), 16), d, N).toString(16);
                        iBeginIndex = iEndIndex;
                        iEndIndex += maxstrlength;
                    }
                    else
                    {
                        //sRetOutStr += (new BigInteger(sHexString.substring(iBeginIndex), 16)).modPow(d, N).toString(16);
                        sRetOutStr += ModPow(new BigInteger(sHexString.substring(iBeginIndex), 16), d, N).toString(16);
                        break;
                    }
                }
                return sRetOutStr;
            }
            else
                return ModPow(new BigInteger(sHexString, 16), d, N).toString(16);
                //return (new BigInteger(sHexString, 16)).modPow(d, N).toString(16);
        }
        public String convertStringToHex(String str)
        {
            char[] chars = str.toCharArray();
            StringBuilder hex = new StringBuilder();
            for(int i = 0; i < chars.length; i++){
                hex.append(Integer.toHexString((int)chars[i]));
            }
            return hex.toString();
        }
        public String convertHexToString(String hex)
        {
            StringBuilder sb = new StringBuilder();
            StringBuilder temp = new StringBuilder();
            //49204c6f7665204a617661 split into two characters 49, 20, 4c...
            for( int i=0; i<hex.length()-1; i+=2 ){
                //grab the hex in pairs
                String output = hex.substring(i, (i + 2));
                //convert hex to decimal
                int decimal = Integer.parseInt(output, 16);
                //convert the decimal to character
                sb.append((char)decimal);
                temp.append(decimal);
            }
            //System.out.println("Decimal : " + temp.toString());
            return sb.toString();
        }
        
        public static boolean isProbablePrime(BigInteger ne, int k) {
		if (ne.compareTo(ONE) == 0)
			return false;
		if (ne.compareTo(THREE) < 0)
			return true;
		int s = 0;
		BigInteger d = ne.subtract(ONE);
		while (d.mod(TWO).equals(ZERO)) {
			s++;
			d = d.divide(TWO);
		}
		for (int i = 0; i < k; i++) {
			BigInteger a = uniformRandom(TWO, ne.subtract(ONE));
			BigInteger x = a.modPow(d, ne);
			if (x.equals(ONE) || x.equals(ne.subtract(ONE)))
				continue;
			int r = 0;
			for (; r < s; r++) {
				x = x.modPow(TWO, ne);
				if (x.equals(ONE))
					return false;
				if (x.equals(ne.subtract(ONE)))
					break;
			}
			if (r == s) // None of the steps made x equal n-1.
				return false;
		}
		return true;
	}

	private static BigInteger uniformRandom(BigInteger bottom, BigInteger top) {
		Random rnd = new Random();
		BigInteger res;
		do {
			res = new BigInteger(top.bitLength(), rnd);
		} while (res.compareTo(bottom) < 0 || res.compareTo(top) > 0);
		return res;
	}
        private static BigInteger ModPow(BigInteger base, BigInteger exponent, final BigInteger modulo) {
                BigInteger result = BigInteger.ONE;
                while (exponent.compareTo(BigInteger.ZERO) > 0) {
                    if (exponent.testBit(0)) // then exponent is odd
                        result = (result.multiply(base)).mod(modulo);
                 exponent = exponent.shiftRight(1);
                 base = (base.multiply(base)).mod(modulo);
               }
                return result.mod(modulo);
        } 
        public static BigInteger inverse (BigInteger a, BigInteger N){
    BigInteger [] ans = extendedEuclid(a,N);
  
    if (ans[1].compareTo(BigInteger.ZERO) == 1)
        return ans[1];
    else return ans[1].add(N);
}

//Calculate d = gcd(a,N) = ax+yN
        //Calculate d = gcd(a,N) = ax+yN
        public static BigInteger [] extendedEuclid (BigInteger a, BigInteger N){
           BigInteger [] ans = new BigInteger[3];
           BigInteger ax, yN;
    
           if (N.equals(BigInteger.ZERO)) {
                ans[0] = a;
                ans[1] = BigInteger.ONE;
                ans[2] = BigInteger.ZERO;
                return ans;
            }

            ans = extendedEuclid (N, a.mod (N));
            ax = ans[1];
            yN = ans[2];
            ans[1] = yN;
            BigInteger temp = a.divide(N);
            temp = yN.multiply(temp);
            ans[2] = ax.subtract(temp);
            return ans;
        }

}
