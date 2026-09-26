package org.diem.crypto;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.util.Arrays;
import java.util.HexFormat;

/** Runs against the same Swift-generated fixtures as the WebCrypto verifier. */
public final class HPKEVectors {
  public static void main(String[] args) throws Exception {
    byte[][] v = Arrays.stream(args).map(HexFormat.of()::parseHex).toArray(byte[][]::new);
    if (v.length != 6) throw new AssertionError("Expected private, public, enc, ciphertext, context, plaintext");
    AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
    parameters.init(new ECGenParameterSpec("secp256r1"));
    PrivateKey key = KeyFactory.getInstance("EC").generatePrivate(
        new ECPrivateKeySpec(new BigInteger(1, v[0]), parameters.getParameterSpec(ECParameterSpec.class)));
    PublicKey publicKey = P256HPKE.decodePublicKey(v[1]);
    if (!Arrays.equals(v[5], P256HPKE.open(key, publicKey, v[2], v[3], v[4]))) {
      throw new AssertionError("HPKE plaintext mismatch");
    }
    for (int index : new int[] {1, 2, 3, 4}) {
      byte[][] wrong = v.clone(); wrong[index] = v[index].clone();
      wrong[index][wrong[index].length - 1] ^= 1;
      try {
        PublicKey wrongPublic = P256HPKE.decodePublicKey(wrong[1]);
        P256HPKE.open(key, wrongPublic, wrong[2], wrong[3], wrong[4]);
        throw new AssertionError("Transplanted context/key or corrupted box accepted");
      } catch (GeneralSecurityException expected) { }
    }
  }
}
