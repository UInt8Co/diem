package org.diem.crypto;

import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;

/** Separate signing and ECDH aliases generated on their destination device.
 * Requires Android 12/API 31 for PURPOSE_AGREE_KEY. No silent software fallback. */
public final class AndroidDeviceKeys {
  public enum Protection { SOFTWARE, TRUSTED_ENVIRONMENT, STRONGBOX }
  private final PrivateKey signing, wrapping;
  private final PublicKey signingPublic, wrappingPublic;
  public final Protection signingProtection, wrappingProtection;

  private AndroidDeviceKeys(String prefix) throws GeneralSecurityException {
    KeyStore store = KeyStore.getInstance("AndroidKeyStore");
    try { store.load(null); } catch (Exception e) { throw new GeneralSecurityException(e); }
    signing = (PrivateKey) store.getKey(prefix + ".sign", null);
    wrapping = (PrivateKey) store.getKey(prefix + ".wrap", null);
    if (signing == null || wrapping == null) throw new GeneralSecurityException("Missing device keys");
    signingPublic = store.getCertificate(prefix + ".sign").getPublicKey();
    wrappingPublic = store.getCertificate(prefix + ".wrap").getPublicKey();
    signingProtection = protection(signing);
    wrappingProtection = protection(wrapping);
  }

  public static AndroidDeviceKeys restore(String prefix) throws GeneralSecurityException {
    return new AndroidDeviceKeys(prefix);
  }
  public static AndroidDeviceKeys generate(String prefix, boolean strongBox, boolean userAuthentication)
      throws GeneralSecurityException {
    if (Build.VERSION.SDK_INT < 31) throw new GeneralSecurityException("ECDH requires API 31");
    if (prefix.isEmpty() || prefix.length() > 128) throw new GeneralSecurityException("Invalid alias");
    KeyStore store = KeyStore.getInstance("AndroidKeyStore");
    try { store.load(null); } catch (Exception e) { throw new GeneralSecurityException(e); }
    if (store.containsAlias(prefix + ".sign") || store.containsAlias(prefix + ".wrap")) {
      throw new GeneralSecurityException("Device aliases already exist");
    }
    try {
      generateKey(prefix + ".sign", KeyProperties.PURPOSE_SIGN, strongBox, userAuthentication);
      generateKey(prefix + ".wrap", KeyProperties.PURPOSE_AGREE_KEY, strongBox, userAuthentication);
      return new AndroidDeviceKeys(prefix);
    } catch (GeneralSecurityException | RuntimeException e) {
      store.deleteEntry(prefix + ".sign"); store.deleteEntry(prefix + ".wrap");
      throw e;
    }
  }
  private static void generateKey(String alias, int purpose, boolean strongBox, boolean auth)
      throws GeneralSecurityException {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", "AndroidKeyStore");
    KeyGenParameterSpec.Builder spec = new KeyGenParameterSpec.Builder(alias, purpose)
        .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
        .setIsStrongBoxBacked(strongBox).setUserAuthenticationRequired(auth);
    if (purpose == KeyProperties.PURPOSE_SIGN) spec.setDigests(KeyProperties.DIGEST_SHA256);
    if (auth) spec.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG);
    generator.initialize(spec.build()); generator.generateKeyPair();
  }
  private static Protection protection(PrivateKey key) throws GeneralSecurityException {
    KeyInfo info = KeyFactory.getInstance(key.getAlgorithm(), "AndroidKeyStore").getKeySpec(key, KeyInfo.class);
    switch (info.getSecurityLevel()) {
      case KeyProperties.SECURITY_LEVEL_STRONGBOX: return Protection.STRONGBOX;
      case KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT: return Protection.TRUSTED_ENVIRONMENT;
      default: return Protection.SOFTWARE;
    }
  }
  public byte[] signingPublicKey() throws GeneralSecurityException { return P256HPKE.encodePublicKey(signingPublic); }
  public byte[] wrappingPublicKey() throws GeneralSecurityException { return P256HPKE.encodePublicKey(wrappingPublic); }
  public byte[] sign(byte[] message) throws GeneralSecurityException {
    if (message.length > 262144) throw new GeneralSecurityException("Message limit");
    Signature signer = Signature.getInstance("SHA256withECDSA");
    signer.initSign(signing); signer.update(message);
    return p1363(signer.sign());
  }
  public byte[] open(byte[] encapsulatedKey, byte[] ciphertext, byte[] context) throws GeneralSecurityException {
    return P256HPKE.open(wrapping, wrappingPublic, encapsulatedKey, ciphertext, context);
  }
  private static byte[] p1363(byte[] der) throws GeneralSecurityException {
    if (der.length < 8 || der.length > 72 || der[0] != 0x30 || (der[1] & 255) != der.length - 2) {
      throw new GeneralSecurityException("ECDSA signature encoding");
    }
    byte[] raw = new byte[64]; int p = 2;
    for (int offset = 0; offset < 64; offset += 32) {
      if (p + 2 > der.length || der[p++] != 2) throw new GeneralSecurityException("ECDSA integer");
      int count = der[p++] & 255;
      if (count == 0 || count > 33 || p + count > der.length || (der[p] & 128) != 0) {
        throw new GeneralSecurityException("ECDSA integer length");
      }
      if (count > 1 && der[p] == 0) {
        if ((der[p + 1] & 128) == 0) throw new GeneralSecurityException("Nonminimal ECDSA integer");
        p++; count--;
      }
      if (count > 32) throw new GeneralSecurityException("ECDSA overflow");
      System.arraycopy(der, p, raw, offset + 32 - count, count); p += count;
    }
    if (p != der.length) throw new GeneralSecurityException("Trailing ECDSA bytes");
    return raw;
  }
}
