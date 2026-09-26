package org.diem.crypto;

import static org.junit.Assert.*;
import org.junit.Test;
import java.util.UUID;

/** Run on an API 31+ physical device. Hardware capability failures are test failures,
 * not silent software fallbacks. StrongBox is a separate explicitly requested run. */
public final class DeviceKeysTest {
  @Test public void deviceGeneratedKeysAndRestoration() throws Exception {
    String prefix = "diem-test-" + UUID.randomUUID();
    try {
      AndroidDeviceKeys keys = AndroidDeviceKeys.generate(prefix, false, false);
      assertTrue(keys.signingProtection != AndroidDeviceKeys.Protection.SOFTWARE);
      assertTrue(keys.wrappingProtection != AndroidDeviceKeys.Protection.SOFTWARE);
      assertFalse(java.util.Arrays.equals(keys.signingPublicKey(), keys.wrappingPublicKey()));
      byte[] message = new byte[] {1, 2, 3};
      byte[] signature = keys.sign(message);
      assertEquals(64, signature.length);
      AndroidDeviceKeys restored = AndroidDeviceKeys.restore(prefix);
      assertTrue(java.util.Arrays.equals(keys.signingPublicKey(), restored.signingPublicKey()));
      assertEquals(64, restored.sign(message).length);
    } finally {
      java.security.KeyStore store = java.security.KeyStore.getInstance("AndroidKeyStore");
      store.load(null); store.deleteEntry(prefix + ".sign"); store.deleteEntry(prefix + ".wrap");
    }
  }
}
