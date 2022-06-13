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
  String msg = timestamp + "::";
  def signatureBytes = hmac_sha256(token, msg);
  StringBuffer hexString = new StringBuffer();
  for (int j=0; j<signatureBytes.length; j++) {
      String hex=Integer.toHexString(0xff & signatureBytes[j]);
      if(hex.length()==1) hexString.append('0');
      hexString.append(hex);
  }
  return hexString.toString();
}

withCredentials([usernamePassword(credentialsId: 'SIGNING_TOKEN', variable: 'SIGNING_TOKEN')]) {
  // the code here can access $SIGNING_TOKEN
  int timestamp = (new Date()).getTime()/1000 as int;
  String encryptedSignature = generate_signiture(timestamp as String, $SIGNING_TOKEN)
  println(encryptedSignature);

  def post = new URL("https://deployments.test.dpty.io/v1/deploy?id=deployment-test-us-west-2&type=ecs").openConnection();
  post.setRequestMethod("POST");
  post.setRequestProperty("Content-Type", "application/json");
  post.setRequestProperty("Accept", "application/json");
  post.setDoOutput(true);
  String jsonInputString = """
    {
      "application": "deployment-test", 
      "isolation_zone": "ops",
      "regions": ["us-west-2"],
      "version": "latest",
      "type": "ecs"
    }
  """;

  post.setRequestProperty("Host", "deployments.test.dpty.io");
  post.setRequestProperty("x-dpty-signature", encryptedSignature);
  post.setRequestProperty("x-dpty-signature-time", timestamp as String);

  try {
    OutputStream os = post.getOutputStream()
    byte[] input = jsonInputString.getBytes("utf-8");
    os.write(input, 0, input.length);			
  } catch(Exception ex) {
    println("getOutputStream", ex);
  }

  try {
    BufferedReader br = new BufferedReader(new InputStreamReader(post.getInputStream(), "utf-8"));
    StringBuilder response = new StringBuilder();
    String responseLine = null;
    while ((responseLine = br.readLine()) != null) {
        response.append(responseLine.trim());
    }
    println(response.toString());
  } catch(Exception ex) {
    println("getInputStream", ex);
  }
}
