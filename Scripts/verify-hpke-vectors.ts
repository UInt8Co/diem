// Opens the committed sealed identity seeds with the independent Java P-256 HPKE receiver.
// Needs a Java 17+ JDK. deno run --allow-read --allow-run --allow-write Scripts/verify-hpke-vectors.ts
const root = new URL("..", import.meta.url).pathname;
const fixture = JSON.parse(await Deno.readTextFile(`${root}/Tests/Vectors/identity-seed.json`));
const classes = await Deno.makeTempDir({ prefix: "diem-hpke-" });
try {
  const compile = await new Deno.Command("javac", { args: ["-d", classes,
    `${root}/Android/src/main/java/org/diem/crypto/P256HPKE.java`,
    `${root}/Android/src/test/java/org/diem/crypto/HPKEVectors.java`],
  }).output();
  if (!compile.success) throw new Error(new TextDecoder().decode(compile.stderr));
  for (const vector of fixture.vectors) for (const v of vector.sealed) {
    const run = await new Deno.Command("java", { args: ["-cp", classes, "org.diem.crypto.HPKEVectors",
      v.recipientPrivateKey, v.recipientPublicKey, v.encapsulatedKey,
      v.ciphertext, v.context, vector.entropy],
    }).output();
    if (!run.success) throw new Error(new TextDecoder().decode(run.stderr));
  }
  console.log(`Opened ${fixture.vectors.length * 2} sealed identity seeds with the Java receiver.`);
} finally {
  await Deno.remove(classes, { recursive: true });
}
