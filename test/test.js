function expect(actual, matcher) {
  if (actual !== matcher) {
    throw new Error(`expect ${matcher}, got ${actual}`);
  }
}

async function runTest() {
  console.log("generate mnemonic");
  const mnemonic = await account.gen();
  expect(mnemonic.mnemonic.split(" ").length, 12);

  console.log("import account from mnemonic");
  const sr25519 = "sr25519";
  const password = "a111111";
  const acc = await account.recover(
    "mnemonic",
    sr25519,
    mnemonic.mnemonic,
    password
  );
  expect(acc.pubKey.length, 66);
  expect(acc.mnemonic, mnemonic.mnemonic);
  expect(acc.encoding.content[1], sr25519);

  console.log("encode address");
  const encoded = await account.encodeAddress([acc.pubKey], [0, 2]);
  expect(encoded[0][acc.pubKey], acc.address);
  console.log("decode address");
  const decoded = await account.decodeAddress([acc.address]);
  expect(decoded[acc.pubKey], acc.address);

  console.log("check password");
  const passCheck = await account.checkPassword(acc.pubKey, "b111111");
  expect(passCheck, null);
  const passCheck2 = await account.checkPassword(acc.pubKey, password);
  expect(passCheck2.success, true);

  console.log("change password");
  const passNew = "c111111";
  const passChangeRes = await account.changePassword(
    acc.pubKey,
    password,
    passNew
  );
  expect(passChangeRes.pubKey, acc.pubKey);
  const passCheck3 = await account.checkPassword(acc.pubKey, password);
  expect(passCheck3, null);
  const passCheck4 = await account.checkPassword(acc.pubKey, passNew);
  expect(passCheck4.success, true);

  return "all tests passed.";
}

window.runTest = runTest;
