package org.diem.crypto;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** RFC 9180 base-mode receiver, suite (DHKEM(P-256, HKDF-SHA256), HKDF-SHA256,
 * AES-256-GCM), sequence zero. ECDH accepts an opaque Android Keystore key.
 * This is a one-message envelope, never a reusable HPKE stream context. */
public final class P256HPKE {
  private P256HPKE() {}
  private static final byte[] KEM = {75, 69, 77, 0, 16};
  private static final byte[] SUITE = {72, 80, 75, 69, 0, 16, 0, 1, 0, 2};
  private static final byte[] VERSION = "HPKE-v1".getBytes(StandardCharsets.US_ASCII);

  public static byte[] open(PrivateKey recipient, PublicKey publicKey, byte[] enc,
      byte[] ciphertext, byte[] context) throws GeneralSecurityException {
    if (ciphertext.length < 16 || ciphertext.length > 262144 || context.length > 262144) {
      throw new GeneralSecurityException("Envelope limit");
    }
    KeyAgreement agreement = KeyAgreement.getInstance("ECDH");
    agreement.init(recipient);
    agreement.doPhase(decodePublicKey(enc), true);
    byte[] dh = agreement.generateSecret();
    byte[] eae = null, shared = null, secret = null, key = null;
    try {
      eae = extract(new byte[0], KEM, "eae_prk", dh);
      shared = expand(eae, KEM, "shared_secret", concat(enc, encodePublicKey(publicKey)), 32);
      byte[] schedule = concat(new byte[] {0},
          extract(new byte[0], SUITE, "psk_id_hash", new byte[0]),
          extract(new byte[0], SUITE, "info_hash", context));
      secret = extract(shared, SUITE, "secret", new byte[0]);
      key = expand(secret, SUITE, "key", schedule, 32);
      byte[] nonce = expand(secret, SUITE, "base_nonce", schedule, 12);
      Cipher aead = Cipher.getInstance("AES/GCM/NoPadding");
      aead.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
      aead.updateAAD(context);
      return aead.doFinal(ciphertext);
    } finally {
      clear(dh); clear(eae); clear(shared); clear(secret); clear(key);
    }
  }

  public static PublicKey decodePublicKey(byte[] encoded) throws GeneralSecurityException {
    if (encoded.length != 65 || encoded[0] != 4) throw new GeneralSecurityException("SEC1 key");
    AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
    parameters.init(new ECGenParameterSpec("secp256r1"));
    ECParameterSpec curve = parameters.getParameterSpec(ECParameterSpec.class);
    ECPoint point = new ECPoint(new BigInteger(1, Arrays.copyOfRange(encoded, 1, 33)),
        new BigInteger(1, Arrays.copyOfRange(encoded, 33, 65)));
    return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(point, curve));
  }

  public static byte[] encodePublicKey(PublicKey key) throws GeneralSecurityException {
    if (!(key instanceof ECPublicKey)) throw new GeneralSecurityException("P-256 key required");
    ECPublicKey ec = (ECPublicKey) key;
    AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
    parameters.init(new ECGenParameterSpec("secp256r1"));
    ECParameterSpec expected = parameters.getParameterSpec(ECParameterSpec.class);
    if (!ec.getParams().getCurve().equals(expected.getCurve())
        || !ec.getParams().getGenerator().equals(expected.getGenerator())
        || !ec.getParams().getOrder().equals(expected.getOrder())) {
      throw new GeneralSecurityException("Wrong curve");
    }
    byte[] encoded = new byte[65]; encoded[0] = 4;
    coordinate(ec.getW().getAffineX(), encoded, 1);
    coordinate(ec.getW().getAffineY(), encoded, 33);
    return encoded;
  }
  private static void coordinate(BigInteger value, byte[] output, int offset)
      throws GeneralSecurityException {
    byte[] bytes = value.toByteArray();
    int start = bytes.length == 33 && bytes[0] == 0 ? 1 : 0;
    int length = bytes.length - start;
    if (value.signum() < 0 || length > 32) throw new GeneralSecurityException("Coordinate");
    System.arraycopy(bytes, start, output, offset + 32 - length, length);
  }
  private static byte[] extract(byte[] salt, byte[] suite, String label, byte[] ikm)
      throws GeneralSecurityException {
    return hmac(salt.length == 0 ? new byte[32] : salt,
        concat(VERSION, suite, label.getBytes(StandardCharsets.US_ASCII), ikm));
  }
  private static byte[] expand(byte[] prk, byte[] suite, String label, byte[] info, int length)
      throws GeneralSecurityException {
    // Every length needed by this suite fits one SHA-256 HKDF block.
    if (length < 1 || length > 32) throw new GeneralSecurityException("HKDF length");
    byte[] labeled = concat(new byte[] {(byte) (length >> 8), (byte) length}, VERSION,
        suite, label.getBytes(StandardCharsets.US_ASCII), info, new byte[] {1});
    return Arrays.copyOf(hmac(prk, labeled), length);
  }
  private static byte[] hmac(byte[] key, byte[] input) throws GeneralSecurityException {
    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec(key, "HmacSHA256"));
    return mac.doFinal(input);
  }
  private static byte[] concat(byte[]... inputs) {
    int count = 0;
    for (byte[] input : inputs) count = Math.addExact(count, input.length);
    byte[] result = new byte[count]; int offset = 0;
    for (byte[] input : inputs) { System.arraycopy(input, 0, result, offset, input.length); offset += input.length; }
    return result;
  }
  private static void clear(byte[] bytes) { if (bytes != null) Arrays.fill(bytes, (byte) 0); }
}
