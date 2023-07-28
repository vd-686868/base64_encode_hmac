import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
public class HMacTest {

    public static final String ALGORITHM = "HmacSHA256";

    public static String calculateHMac(String key, String data) throws Exception {
        Mac sha256_HMAC = Mac.getInstance(ALGORITHM);
        SecretKeySpec secret_key = new SecretKeySpec(key.getBytes("UTF-8"), ALGORITHM);
        sha256_HMAC.init(secret_key);

        return byteArrayToHex(sha256_HMAC.doFinal(data.getBytes("UTF-8")));
    }

    public static String byteArrayToHex(byte[] a) {
        StringBuilder sb = new StringBuilder(a.length * 2);
        for(byte b: a)
            sb.append(String.format("%02x", b));
        return sb.toString();
    }

    public static void main(String [] args) throws Exception {
        String originalDigest = calculateHMac(yourSecretKey, "GET+/hello/+27Jul202323:22:43+your_nonce");
        String encodedDigest = Base64.getEncoder().encodeToString(originalDigest.getBytes());
        System.out.println(encodedDigest);
    }
}
