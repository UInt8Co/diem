// Opens the committed sealed identity keys with the independent Java P-256 HPKE receiver.
// Needs a Java 17+ JDK. deno run --allow-read --allow-run --allow-write Scripts/verify-hpke-vectors.ts
const root = new URL("..", import.meta.url).pathname;
const fixture = JSON.parse(await Deno.readTextFile(`${root}/Tests/Vectors/diem-v3.json`));
const classes = await Deno.makeTempDir({ prefix: "diem-hpke-" });
try {
  const compile = await new Deno.Command("javac", { args: ["-d", classes,
    `${root}/Android/src/main/java/org/diem/crypto/P256HPKE.java`,
    `${root}/Android/src/test/java/org/diem/crypto/HPKEVectors.java`],
  }).output();
  if (!compile.success) throw new Error(new TextDecoder().decode(compile.stderr));
  for (const v of fixture.vectors) {
    const run = await new Deno.Command("java", { args: ["-cp", classes, "org.diem.crypto.HPKEVectors",
      v.recipientPrivateKey, v.recipientPublicKey, v.sealEncapsulatedKey,
      v.sealCiphertext, v.sealContext, v.identityPrivateKey],
    }).output();
    if (!run.success) throw new Error(new TextDecoder().decode(run.stderr));
  }
  console.log(`Opened ${fixture.vectors.length} sealed identity keys with the Java receiver.`);
} finally {
  await Deno.remove(classes, { recursive: true });
}
