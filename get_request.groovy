import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;

def hmac_sha256(String secretKey, String data) {
 try {
    Mac mac = Mac.getInstance("HmacSHA256")
    SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getBytes(), "HmacSHA256")
    mac.init(secretKeySpec)
    byte[] digest = mac.doFinal(data.getBytes())
    return digest
   } catch (InvalidKeyException e) {
    throw new RuntimeException("Invalid key exception while converting to HMac SHA256")
  }
}

def generate_signiture(String timestamp, String token){
  String msg = timestamp as String;
  msg = msg + "::";
  def signatureBytes = hmac_sha256(token, msg);
  StringBuffer hexString = new StringBuffer();
  for (int j=0; j<signatureBytes.length; j++) {
      String hex=Integer.toHexString(0xff & signatureBytes[j]);
      if(hex.length()==1) hexString.append('0');
      hexString.append(hex);
  }
  return hexString.toString();
}

withCredentials([string(credentialsId: 'SIGNING_TOKEN', variable: 'SIGNING_TOKEN')]) {
  // the code here can access $SIGNING_TOKEN
  int timestamp = (new Date()).getTime()/1000 as int;
  String encryptedSignature = generate_signiture(timestamp as String, $SIGNING_TOKEN)
  println(encryptedSignature);

  def get = new URL("https://deployments.test.dpty.io/v1/deploy?id=deployment-test-us-west-2&type=ecs").openConnection();
  get.setRequestProperty("Host", "deployments.test.dpty.io");
  get.setRequestProperty("x-dpty-signature", encryptedSignature);
  get.setRequestProperty("x-dpty-signature-time", timestamp as String);

  def getRC = get.getResponseCode();
  println(getRC);
  if (getRC.equals(200)) {
      println(get.getInputStream().getText());
  }

}
