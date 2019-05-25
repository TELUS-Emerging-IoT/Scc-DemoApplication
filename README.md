# Scc-DemoApplication
This is a guide on how to setup and run the demo3 application utilizing the GD library.

The scc toolkit provides various security key features abstracted for easy implementation. To compile and run the application do the following.

1. On the raspberry pi, cd to the following directory:
```
/home/pi/Downloads/demo/scc-lib/demo-src
```
2. Compile the demo3.cpp file:

In the .../scc-lib/demo-src folder, issue the following command:

```
g++ demo3.cpp -lscc-toolkit -lssl -lcrypto -o demo3 -std=c++17

```
3. run the demo3 executable via the command: 

```
./demo3
```
4. The output should look like the following:

![alt text](images/4exampleout.png)

If the program throws a CME error, then the BG96 may require a firmware upgrade, please see the following tutorial:

https://github.com/TELUS-Emerging-IoT/TELUS-IoT-BG96-Firmware-Update

## demo3 output
For reference the output of the code is included below alongside some additional comments on what each section does. Overall demo3 showcases the various keys availible to the user. More information can be found within the demo3 source file and the scc-toolkit headers.

I. AES
II. HMAC
III. RSA
IV. ECC

```
High Level SCC Application: Demo3
Opened Modem [/dev/ttyUSB2]
***************************
*** Delete All Entries ****
***************************
Erased all Entries

************************
*** Generate Random  ***
************************
Random: 75 7B 8F A8 9C BD 14 E4 7C 78 1D 6F 29 56 1A A6 71 E4 8D DD EF 1F 43 D1 57 6C 97 2F F9 91 50 A6 AC 65 36 CA 2D 5A 04 0B DA AF 1A 3D 35 9E 29 6D 93 69 3F 88 44 82 73 B3 17 50 F3 1C FC 96 7C 38 EB 77 09 5D 5F D1 D0 7E B4 7D 2B 4B 93 63 5D F9 38 EA 53 7A 8B E4 6B 4D 22 16 E2 83 72 7D 5B BE D7 14 06 1C 52 75 FA 73 DC 38 EB 24 14 8C 7C CF 38 4C 6B 37 60 9B 59 CD A9 4E 6A 23 C2 8B DC 77 7F 42 FC 16 55 D2 4F BF 26 AB BC FB BB 6A EA 33 39 4D B1 9F C6 76 26 0E 41 D2 33 51 60 7E 13 60 ED 65 1C 1E 96 8E 2C 19 91 57 5C 9F 6B 2A 0A 91 9B E4 6C 64 6E 8B 4C 1C C3 AA 04 42 30 DE 1E 78 8F B0 00 22 3A 8C B2 06 CE 57 27 C5 6C 80 72 FD 7C 3E FF A1 63 34 21 BD 65 E4 70 C5 4B F8 B1 6E 12 88 B2 66 13 FF C7 01 A8 D0 2A 15 04 C0 DA C0 73 A5 D0 3F 74 EC DC 09 DC 7C D3 99 CD A5 AC ED 43 27 15 89 30 EA 3C D3 7D 2D 2C 5A 50 12 D7 4D 27 0E 1D 0D 1F 4C E9 A7 6E BB FF DC 62 0B 17 AC 47 AE F4 66 7B EB 77 C7 C3 F3 E9 85 28 D9 C6 F1 2F 2C 4D CE EB 96 1F 16 85 6A FF 64 2F 51 D6 AE 1B DB E3 CA D3 7B 48 F2 28 AB 6E 2A E1 9C 87 16 E0 70 1A D6 8E F9 5A 77 BC B4 F5 B3 8D 28 9B DA A7 67 8E E6 BB B0 B6 BA EA 2E 14 4B 5F 83 33 FE FD 2D 3A 35 C1 C5 51 2B 5F 10 F0 72 2A 34 8C D7 3F D2 7A 7A 1F F0 3B D1 10 58 AD E2 86 4B 70 2B FD FD 9A B2 E5 50 18 A2 65 F9 DD 41 6A 71 A7 A1 7F 73 00 AD 5A D6 40 77 98 EA F0 1F 30 79 A0 2E C9 E0 ED F6 2E 64 97 6C E2 50 AE 2B C7 4B 1D F4 C5 8B AD 3F E8 34 D6 AE A3 4C 76 7C AF 8B D1 84 37 62 1F DF D9 94 CD 19 38 6F 8E D1 C4 0D 63 07 27 D6 B0 74 2D FF D1 8D 2D 8B 80 0A A7 8F A6 AD 52 3B 65 BD 36 1D 40 02 98 A0 09 8B 29 A8 BE 1A
**********************
*** Secure Storage ***
**********************
***************
I.  AES Key ***
***************

///First we create an AES Key proxy on UICC, this key is then used to encrpyt and decrpyt data
///The data encrpyted here is the octet strings of 0s,1s,2s, and 3s same as the deciphertext
///we instantiate a scc::SCC_AESKey object and call it aeskey then encrypt the data by calling the command aeskey.initCipher();

AES Key ID: [5000] [5000]
Encrypting ...
  Ciphertext:   18 99 56 4A 9D A8 DE 83 3D 25 C7 17 39 EA AD CE
  Ciphertext:   56 99 5E 11 48 37 13 A0 9E 12 7F B9 CE 26 78 09
  Ciphertext:   DB DE 4C 54 F4 41 0F AE 7F 2E EA CD 00 AE 02 19
  Ciphertext:   28 CC 83 B5 CE 6D A7 91 44 81 67 F6 F9 EE 6A 28

///Now we want to decipher the data, we call the following aeskey.initCipher(false);

Decrypting ...
  Deciphertext: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  Deciphertext: 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11
  Deciphertext: 22 22 22 22 22 22 22 22 22 22 22 22 22 22 22 22
  Deciphertext: 33 33 33 33 33 33 33 33 33 33 33 33 33 33 33 33
*******************************
*** AES Convenience Methods ***
*******************************
Using application methods ...

// Data can be encrypted by calling encrpyt on an SCC_Application object (i.e. sccApp.encrpyt)

OctetString encrypt(
                    int keyId,
                    const OctetString& data,
                    SSAlgorithm algorithm=SSAlgorithm::AES_BLOCK_128_ECB_NOPAD
                    );

//This returns a string of cipher text


 App method Encrypt:   5C 0A 37 B7 C8 D2 B8 E2 5C E7 94 70 7D DB 1B 93 5C 0A 37 B7 C8 D2 B8 E2 5C E7 94 70 7D DB 1B 93 5C 0A 37 B7 C8 D2 B8 E2 5C E7 94 70 7D DB 1B 93 5C 0A 37 B7 C8 D2 B8 E2 5C E7 94 70 7D DB 1B 93 5C 0A 37 B7 C8 D2 B8 E2 5C E7 94 70 7D DB 1B 93 5C 0A 37 B7 C8 D2 B8 E2 5C E7 94 70 7D DB 1B 93


//The cipher text is decrypted by calling decrypt on the SCC_Application object (i.e. sccApp.decrypt)
OctetString decrypt(
                    int keyId,
                    const OctetString& data,
                    SSAlgorithm algorithm=SSAlgorithm::AES_BLOCK_128_ECB_NOPAD
                    );
//Now the text is deciphered


App method Decrypt:   AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA

// Calling encrpyt on a key type (aeskey.encrypt(data_block))

Using key methods ...
  Key method Encrypt:   5C 0A 37 B7 C8 D2 B8 E2 5C E7 94 70 7D DB 1B 93 5C 0A 37 B7 C8 D2 B8 E2 5C E7 94 70 7D DB 1B 93 5C 0A 37 B7 C8 D2 B8 E2 5C E7 94 70 7D DB 1B 93 5C 0A 37 B7 C8 D2 B8 E2 5C E7 94 70 7D DB 1B 93 5C 0A 37 B7 C8 D2 B8 E2 5C E7 94 70 7D DB 1B 93 5C 0A 37 B7 C8 D2 B8 E2 5C E7 94 70 7D DB 1B 93

//Calling decrypt on the cipher text returns the message (aeskey.decrypt(cipher_text))

  Key method Decrypt:   AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA

//Here we get the key in plain text via aeskey.get()

Read key value
  Plain key: 40 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F

//here we update the key
void update(
                std::optional<int> newKeyId,
                std::optional<const std::string> newLabel,
                std::optional<SSPermission> newPermission,
                const OctetString& newData
                );

//we do not enable a read permission hence the output

  Updated Plain key:   [Key could not be read]

//we are done with the key and now delete it (aeskey.deleteKey())

Delete key from UICC

****************
II. HMAC Key  **
****************

// we create a new HMAC Key

sccApp.createKey(
                    0x5010,
                    "hmacKey",
                    scc::SSPermission::None,
                    scc::SSKeyType::HMAC,
                    scc::SSKeyLen::HMAC_512,
                    scc::OctetString::fromHexString(
                        "505152535455565758595a5b5c5d5e5f"
                        "606162636465666768696a6b6c6d6e6f"
                        "707172737475767778797a7b7c7d7e7f"
                        "808182838485868788898a8b8c8d8e8f")
                    );
//construct an HMAC key proxy for the key on UICC with label hmacKey
        scc::SCC_HMACKey hmacKey {sccApp, "hmacKey", scc::SSAlgorithm::HMAC_SHA_512 };

// and display the key id, hmacKey.getKeyId()


HMAC Key ID: [5010]

//now we use the key to sign several blocks of data hmacKey.initSign()
// then store the signature hmacSignature = hmacKey.signFinal(data_block)

Signing ...
  Signature:   1A EF 75 46 44 F4 69 63 EF 77 86 29 DA A3 4A 3B 3B 48 47 1B BB DA 9C 09 A6 EE E5 58 FF E0 06 FF B1 C6 B3 70 EC 89 61 D5 2C D6 D8 0C F3 51 11 EB 49 F5 8C 2B FB 92 FE 74 F0 43 5F 52 15 A5 81 7F

//Now we veriy the HMAC signature, however you must know the length of the message (hmacKey.initVerify)
//hmacKey.verifyFirst(messageLen,data_block);
//iterate through each block hmacKey.verifyNexy(data_block)

Verifying ...

//Verify final block and see the signature is fine hmacKey.verifyFinal(data_block, hmacSignature);

  Verify:   1
********************************
*** HMAC Convenience Methods ***
********************************

//we use the application methods for smaller blocks of data

hmacShortSignature = sccApp.sign(
                    hmacKey.getKeyId(),
                    blk,
                    scc::SSAlgorithm::HMAC_SHA_512
                    );

Using application methods ...
  App method Signature:   9C 26 C9 B0 C5 17 18 6B 39 ED 10 8E ED 91 E9 25 3D BE FA 66 A4 0E 24 18 FD CA 5F E9 5F BF 8E 04 5C F4 AE 9F F9 10 AB 50 0C 9D 33 64 3F B3 7F FA 0A B7 F1 76 61 9A 1F C2 56 78 30 26 32 3E B1 59

//Now we verify

 hmacShortVerify = sccApp.verify(
                    hmacKey.getKeyId(),
                    blk,
                    hmacShortSignature,
                    scc::SSAlgorithm::HMAC_SHA_512
                    );

  App method Verify:   1

//Now we do the same thing again but with the key methods hmacKey.sign(data_block);

Using key methods ...
  Key method Signature:   9C 26 C9 B0 C5 17 18 6B 39 ED 10 8E ED 91 E9 25 3D BE FA 66 A4 0E 24 18 FD CA 5F E9 5F BF 8E 04 5C F4 AE 9F F9 10 AB 50 0C 9D 33 64 3F B3 7F FA 0A B7 F1 76 61 9A 1F C2 56 78 30 26 32 3E B1 59

// hmacKey.verify(data_blk, hmacShortSignature1);

  Key method Verify:   1
***********************
III. RSA Private Key **
************************

// First create a key  ////////////////////////////////////////////////////////////////////////
        // First create the key
        ////////////////////////////////////////////////////////////////////////
        auto privateExponent { scc::OctetString::fromHexString(
                "86fee9febb3ca55a551ed1c5a76e81c5b1cb06287f9297a48fd5b73960707b90"
                "ec2b32cc4bc993c7b0211f8951bce30c1aee3382169f02827a85b18cb42a810e"
                "db6d62eeadef98c0f38c20b6f0f697afca707ef9c172bc8b4d90cbfd16e3ab6a"
                "5c43a54056dfd681175294566e4a60df01faf83640ca4d09d1fb100e1dc8c981"
                "4c70dba698d65f78810fc48b947ee0affe7a38c22368bb3cf300dab1fb658af8"
                "19123c07f61f1fb57cbe69ee1478a3122b87e34f1a4d4c8ae9512eb94a3e52b9"
                "c1456556c0c58ad71e045e212b5e2f4f63c29bc612044f7f1578fd8d08feb0fa"
                "8138dafecd017bd010db0da48045d38c47cf47a383f4e6733c31b8e8de5faa21"
                )};
        auto publicExponent { scc::OctetString::fromHexString("010001")};
        auto modulus { scc::OctetString::fromHexString(
                "d4562bc18f179bf7c1ed56f76afe8b8bc68b7881e59970199afafe3024a15814"
                "00e8fa5500450202c0830a0df1511e84872f307a8d0cf893252c400f9140fff2"
                "698853d49a7a03848dfc052e0dded9b65b8c7fe8cd6fe57208fedde323f2986f"
                "6d6a05037429524672798d8139fe3365d3422f76eb45f1802c12265ef977ddf5"
                "0285905b9bcd77ce1f48c33cd2c315ff6caeb1859579a5b53cd3cf40633c9594"
                "2deb6431db786824468abc0600f8a38f83c7c576ed510fe5adba0e1bc433d913"
                "6da89d894f3f4e1e2523fae1fac0cc4c7d7f4d7c06e88708e7abf3c084b648ad"
                "d6927faa673e8505aad0ae74aba05ac9e1d98cb0f89965d011179f63c1ef0749"
                )};


        sccApp.createKey(
                    0x5020,
                    "rsaPrivateKey",
                    scc::SSPermission::Write,
                    scc::SSKeyType::RSA_Private,
                    scc::SSKeyLen::RSA_2048,
                    privateExponent,
                    modulus
                    );

//construct an RSAPrivateKey proxy for the key on UICC with label rsaPrivateKey
        scc::SCC_RSAPrivateKey rsaPrivateKey {sccApp, "rsaPrivateKey"};



 ////////////////////////////////////////////////////////////////////////
        // Now sign a dataset of 500*60=30K some data using it
        ////////////////////////////////////////////////////////////////////////
        rsaPrivateKey.initSign();

        for (int i=0; i < numBlocks-1; i++)
           rsaPrivateKey.signNext(blk);

        auto rsaSignature = rsaPrivateKey.signFinal(blk);

RSA Private Key ID: [5020]
  Signature:   5B D4 B3 80 69 76 F5 3B A3 B8 02 2B 58 95 4C FF 3A 23 E5 A9 A0 C8 74 B4 8D DF 12 80 54 2C 8D 75 73 92 4E 7B CD 47 B0 71 B3 53 3D 9B AD 74 C4 B2 0F 80 F8 0A 01 61 D5 A9 7D B7 04 BE CE 3F 10 27 B2 20 90 E9 4A 33 AD 3E 43 70 D3 BE 07 93 08 26 50 9F F4 24 44 31 DF 7A 52 31 F1 FF 6E D0 61 9C 92 1E 23 B2 DD 6B 32 1E CC 70 3C 69 BD ED 2A C5 DF 81 17 92 1A 05 39 29 68 6D 6D 13 54 AE 12 63 CB E4 3E 74 AF BB E5 70 AD 12 39 53 EC 90 63 F5 4C 62 C8 64 9D 59 BA D2 D9 27 AF 51 D9 83 48 3B 5C 4B EF E7 B0 C3 13 7A 5E DE 87 2A A1 F8 DE AA F3 7E 68 DE 3F C9 22 9A 62 18 2D 6F 1B 4E E4 4A 83 4F 75 4E 28 DE 04 5E 69 69 EC 3C 36 51 67 8F DF FB 05 40 43 E1 9E F3 AD 0A D4 B0 8E 9F 1B 36 57 7D E9 6D 3F 09 4F 28 42 14 24 BC F1 9F 08 05 7F E9 53 52 51 DF 76 9D 9A 16 E1 19 C2 90 57 03
**********************
*** RSA Public Key ***
**********************

 ////////////////////////////////////////////////////////////////////////
        // First create the key
        // the modulus is defined above
        ////////////////////////////////////////////////////////////////////////
        sccApp.createKey(
                    0x5021,
                    "rsaPublicKey",
                    scc::SSPermission::Write,
                    scc::SSKeyType::RSA_Public,
                    scc::SSKeyLen::RSA_2048,
                    publicExponent,
                    modulus
                    );

        //construct an RSAPublicKey proxy for the key on UICC with label rsaPrivateKey
        scc::SCC_RSAPublicKey rsaPublicKey {sccApp, "rsaPublicKey"};



RSA Public Key ID: [5021]

// Now verify the RSA signature

Verifying ...

// The following code verifies the key
 rsaPublicKey.initVerify();

        rsaPublicKey.verifyFirst(messageLen, blk);
        for (int i=0; i < numBlocks-2; i++)
           rsaPublicKey.verifyNext(blk);


        auto rsaVerify = rsaPublicKey.verifyFinal(blk, rsaSignature);

// and here it returns true

  Verify:   1
***********************
*** RSA Certificate ***
***********************

// First create the certificate
auto rsaCertData = readCert("../examples/card-NewYorkCity-der.crt");

 sccApp.createCertificate(
                    0x5022,
                    "rsaCert",
                    rsaCertData
                    );
// and we can see the cert data below

Certificate: 30 82 02 69 30 82 02 0F 02 09 00 8D 66 2A B1 E4 70 2F 06 30 0A 06 08 2A 86 48 CE 3D 04 03 02 30 81 87 31 0B 30 09 06 03 55 04 06 13 02 55 53 31 0B 30 09 06 03 55 04 08 0C 02 56 41 31 0F 30 0D 06 03 55 04 07 0C 06 44 75 6C 6C 65 73 31 0F 30 0D 06 03 55 04 0A 0C 06 47 44 4D 53 41 49 31 0B 30 09 06 03 55 04 0B 0C 02 4D 53 31 15 30 13 06 03 55 04 03 0C 0C 45 72 69 63 20 4A 6F 68 6E 73 6F 6E 31 25 30 23 06 09 2A 86 48 86 F7 0D 01 09 01 16 16 65 72 69 63 2E 6A 6F 68 6E 73 6F 6E 40 67 69 2D 64 65 2E 63 6F 6D 30 1E 17 0D 31 37 31 31 31 30 30 34 34 39 34 30 5A 17 0D 31 38 31 31 31 30 30 34 34 39 34 30 5A 30 26 31 24 30 22 06 03 55 04 03 0C 1B 4E 65 77 59 6F 72 6B 43 69 74 79 40 72 73 61 2E 69 6F 74 2E 61 74 74 2E 63 6F 6D 30 82 01 22 30 0D 06 09 2A 86 48 86 F7 0D 01 01 01 05 00 03 82 01 0F 00 30 82 01 0A 02 82 01 01 00 D4 56 2B C1 8F 17 9B F7 C1 ED 56 F7 6A FE 8B 8B C6 8B 78 81 E5 99 70 19 9A FA FE 30 24 A1 58 14 00 E8 FA 55 00 45 02 02 C0 83 0A 0D F1 51 1E 84 87 2F 30 7A 8D 0C F8 93 25 2C 40 0F 91 40 FF F2 69 88 53 D4 9A 7A 03 84 8D FC 05 2E 0D DE D9 B6 5B 8C 7F E8 CD 6F E5 72 08 FE DD E3 23 F2 98 6F 6D 6A 05 03 74 29 52 46 72 79 8D 81 39 FE 33 65 D3 42 2F 76 EB 45 F1 80 2C 12 26 5E F9 77 DD F5 02 85 90 5B 9B CD 77 CE 1F 48 C3 3C D2 C3 15 FF 6C AE B1 85 95 79 A5 B5 3C D3 CF 40 63 3C 95 94 2D EB 64 31 DB 78 68 24 46 8A BC 06 00 F8 A3 8F 83 C7 C5 76 ED 51 0F E5 AD BA 0E 1B C4 33 D9 13 6D A8 9D 89 4F 3F 4E 1E 25 23 FA E1 FA C0 CC 4C 7D 7F 4D 7C 06 E8 87 08 E7 AB F3 C0 84 B6 48 AD D6 92 7F AA 67 3E 85 05 AA D0 AE 74 AB A0 5A C9 E1 D9 8C B0 F8 99 65 D0 11 17 9F 63 C1 EF 07 49 02 03 01 00 01 30 0A 06 08 2A 86 48 CE 3D 04 03 02 03 48 00 30 45 02 21 00 AF 63 AB A5 38 CD 77 0A A6 D0 FD B5 F4 17 5A AD 48 0F D9 EB 2E A8 7F 74 66 2D 77 0D 51 F8 51 24 02 20 55 D7 0F EB BC E5 67 4E BC 3A 7F 62 8B D7 BA 25 75 12 DA E3 39 0E 41 4B 46 83 26 83 2B 4D 8D 53

//We can also readout the cert data using the label of the entry "rsaCert"
rsaCertValue =  sccApp.getCert("rsaCert");
//here we show the certificate once again

Certificate: 30 82 02 69 30 82 02 0F 02 09 00 8D 66 2A B1 E4 70 2F 06 30 0A 06 08 2A 86 48 CE 3D 04 03 02 30 81 87 31 0B 30 09 06 03 55 04 06 13 02 55 53 31 0B 30 09 06 03 55 04 08 0C 02 56 41 31 0F 30 0D 06 03 55 04 07 0C 06 44 75 6C 6C 65 73 31 0F 30 0D 06 03 55 04 0A 0C 06 47 44 4D 53 41 49 31 0B 30 09 06 03 55 04 0B 0C 02 4D 53 31 15 30 13 06 03 55 04 03 0C 0C 45 72 69 63 20 4A 6F 68 6E 73 6F 6E 31 25 30 23 06 09 2A 86 48 86 F7 0D 01 09 01 16 16 65 72 69 63 2E 6A 6F 68 6E 73 6F 6E 40 67 69 2D 64 65 2E 63 6F 6D 30 1E 17 0D 31 37 31 31 31 30 30 34 34 39 34 30 5A 17 0D 31 38 31 31 31 30 30 34 34 39 34 30 5A 30 26 31 24 30 22 06 03 55 04 03 0C 1B 4E 65 77 59 6F 72 6B 43 69 74 79 40 72 73 61 2E 69 6F 74 2E 61 74 74 2E 63 6F 6D 30 82 01 22 30 0D 06 09 2A 86 48 86 F7 0D 01 01 01 05 00 03 82 01 0F 00 30 82 01 0A 02 82 01 01 00 D4 56 2B C1 8F 17 9B F7 C1 ED 56 F7 6A FE 8B 8B C6 8B 78 81 E5 99 70 19 9A FA FE 30 24 A1 58 14 00 E8 FA 55 00 45 02 02 C0 83 0A 0D F1 51 1E 84 87 2F 30 7A 8D 0C F8 93 25 2C 40 0F 91 40 FF F2 69 88 53 D4 9A 7A 03 84 8D FC 05 2E 0D DE D9 B6 5B 8C 7F E8 CD 6F E5 72 08 FE DD E3 23 F2 98 6F 6D 6A 05 03 74 29 52 46 72 79 8D 81 39 FE 33 65 D3 42 2F 76 EB 45 F1 80 2C 12 26 5E F9 77 DD F5 02 85 90 5B 9B CD 77 CE 1F 48 C3 3C D2 C3 15 FF 6C AE B1 85 95 79 A5 B5 3C D3 CF 40 63 3C 95 94 2D EB 64 31 DB 78 68 24 46 8A BC 06 00 F8 A3 8F 83 C7 C5 76 ED 51 0F E5 AD BA 0E 1B C4 33 D9 13 6D A8 9D 89 4F 3F 4E 1E 25 23 FA E1 FA C0 CC 4C 7D 7F 4D 7C 06 E8 87 08 E7 AB F3 C0 84 B6 48 AD D6 92 7F AA 67 3E 85 05 AA D0 AE 74 AB A0 5A C9 E1 D9 8C B0 F8 99 65 D0 11 17 9F 63 C1 EF 07 49 02 03 01 00 01 30 0A 06 08 2A 86 48 CE 3D 04 03 02 03 48 00 30 45 02 21 00 AF 63 AB A5 38 CD 77 0A A6 D0 FD B5 F4 17 5A AD 48 0F D9 EB 2E A8 7F 74 66 2D 77 0D 51 F8 51 24 02 20 55 D7 0F EB BC E5 67 4E BC 3A 7F 62 8B D7 BA 25 75 12 DA E3 39 0E 41 4B 46 83 26 83 2B 4D 8D 53
RSA Certificate ID: [5022]

//we verify the RSA Certificate

Verifying ...
  Verify:   1


*******************************
*** RSA Convenience Methods ***
*******************************

//Now we use the application convience methods for smaller blocks
 auto rsaShortSignature = sccApp.sign(
                    rsaPrivateKey.getKeyId(),
                    blk,
                    scc::SSAlgorithm::RSA_SHA_256_PKCS1
                    );
// and we see the signature

Using Application methods ...
  App method Signature:   18 06 14 58 7C 00 2B B9 59 94 37 1E 19 25 7C 48 9F 23 99 40 DC 40 28 55 19 92 EA 44 0B 11 70 79 75 70 ED C7 07 BE B8 8B C9 3E 5A C1 B2 85 C4 53 56 93 C7 EF 2B 9E 90 E5 97 09 E3 3B 04 D0 4D 55 D1 66 2B 29 58 C1 55 92 72 32 62 B7 5D 9F B1 53 5B DF DB E3 3A 90 EB 0D 37 7D 8B 39 33 DC FC C1 02 0B 5D 66 4A A4 1A 18 87 26 06 36 C7 92 56 2A 47 C6 21 E8 19 DB 44 BD 40 7B C4 25 17 8E 3D B6 BA 28 79 1E E1 6D 52 2D 33 62 09 69 54 D6 BD 10 B4 03 43 29 A2 B0 14 4F A7 94 DC FB 4C 51 3E B4 EE 52 00 85 7E 81 F3 09 F1 6E B3 05 79 B5 0B 69 67 24 0D B5 2D BA E3 2E 49 F7 2F 13 C3 80 7B A9 18 E9 BA 77 1D 7F 27 39 A0 A4 D9 2B BA 02 CB 65 92 59 02 6A 62 AB 96 C2 38 7F BE 24 F0 9B AC F2 17 FB DC 71 F0 CF 2A 67 83 88 2E 67 1F AE 29 34 1D C1 E3 F7 91 79 CA A5 B1 70 B4 EF 5C 33 77 21

//Now we use the precomputed hash and see that the result is the same

  App method Signature: (pre-computed hash)  18 06 14 58 7C 00 2B B9 59 94 37 1E 19 25 7C 48 9F 23 99 40 DC 40 28 55 19 92 EA 44 0B 11 70 79 75 70 ED C7 07 BE B8 8B C9 3E 5A C1 B2 85 C4 53 56 93 C7 EF 2B 9E 90 E5 97 09 E3 3B 04 D0 4D 55 D1 66 2B 29 58 C1 55 92 72 32 62 B7 5D 9F B1 53 5B DF DB E3 3A 90 EB 0D 37 7D 8B 39 33 DC FC C1 02 0B 5D 66 4A A4 1A 18 87 26 06 36 C7 92 56 2A 47 C6 21 E8 19 DB 44 BD 40 7B C4 25 17 8E 3D B6 BA 28 79 1E E1 6D 52 2D 33 62 09 69 54 D6 BD 10 B4 03 43 29 A2 B0 14 4F A7 94 DC FB 4C 51 3E B4 EE 52 00 85 7E 81 F3 09 F1 6E B3 05 79 B5 0B 69 67 24 0D B5 2D BA E3 2E 49 F7 2F 13 C3 80 7B A9 18 E9 BA 77 1D 7F 27 39 A0 A4 D9 2B BA 02 CB 65 92 59 02 6A 62 AB 96 C2 38 7F BE 24 F0 9B AC F2 17 FB DC 71 F0 CF 2A 67 83 88 2E 67 1F AE 29 34 1D C1 E3 F7 91 79 CA A5 B1 70 B4 EF 5C 33 77 21

// Now we verify


/ auto rsaShortVerify = sccApp.verify(
/                    rsaPublicKey.getKeyId(),
/                    blk,
/                    rsaShortSignature,
/                    scc::SSAlgorithm::RSA_SHA_256_PKCS1
/                    );

  App method Verify (PublicKey):   1

/        auto rsaShortCertVerify = sccApp.verify(
/                    rsaCert.getId(),
/                    blk,
/                    rsaShortSignature,
/                    scc::SSAlgorithm::RSA_SHA_256_PKCS1
/                    );


  App method Verify (Cert):   1

/  auto rsaPreComputedCertVerify = sccApp.verify(
/                    rsaCert.getId(),
/                    blk,
/                    rsaShortSignature,
/                    scc::SSAlgorithm::RSA_SHA_256_PKCS1
/                    );

  Key method Verify pre-computed hash signature (Cert):   1

// Now we can use the key method for small blocks of data

Using key methods ...

/auto rsaShortSignature1 = rsaPrivateKey.sign(blk);

  Key method Signature:   18 06 14 58 7C 00 2B B9 59 94 37 1E 19 25 7C 48 9F 23 99 40 DC 40 28 55 19 92 EA 44 0B 11 70 79 75 70 ED C7 07 BE B8 8B C9 3E 5A C1 B2 85 C4 53 56 93 C7 EF 2B 9E 90 E5 97 09 E3 3B 04 D0 4D 55 D1 66 2B 29 58 C1 55 92 72 32 62 B7 5D 9F B1 53 5B DF DB E3 3A 90 EB 0D 37 7D 8B 39 33 DC FC C1 02 0B 5D 66 4A A4 1A 18 87 26 06 36 C7 92 56 2A 47 C6 21 E8 19 DB 44 BD 40 7B C4 25 17 8E 3D B6 BA 28 79 1E E1 6D 52 2D 33 62 09 69 54 D6 BD 10 B4 03 43 29 A2 B0 14 4F A7 94 DC FB 4C 51 3E B4 EE 52 00 85 7E 81 F3 09 F1 6E B3 05 79 B5 0B 69 67 24 0D B5 2D BA E3 2E 49 F7 2F 13 C3 80 7B A9 18 E9 BA 77 1D 7F 27 39 A0 A4 D9 2B BA 02 CB 65 92 59 02 6A 62 AB 96 C2 38 7F BE 24 F0 9B AC F2 17 FB DC 71 F0 CF 2A 67 83 88 2E 67 1F AE 29 34 1D C1 E3 F7 91 79 CA A5 B1 70 B4 EF 5C 33 77 21

// Now with the precomputedHash auto rsaPreComputedSignature1 = rsaPrivateKey.sign(precomputedHash, true);

  Key method Signature (pre-computed hash): 18 06 14 58 7C 00 2B B9 59 94 37 1E 19 25 7C 48 9F 23 99 40 DC 40 28 55 19 92 EA 44 0B 11 70 79 75 70 ED C7 07 BE B8 8B C9 3E 5A C1 B2 85 C4 53 56 93 C7 EF 2B 9E 90 E5 97 09 E3 3B 04 D0 4D 55 D1 66 2B 29 58 C1 55 92 72 32 62 B7 5D 9F B1 53 5B DF DB E3 3A 90 EB 0D 37 7D 8B 39 33 DC FC C1 02 0B 5D 66 4A A4 1A 18 87 26 06 36 C7 92 56 2A 47 C6 21 E8 19 DB 44 BD 40 7B C4 25 17 8E 3D B6 BA 28 79 1E E1 6D 52 2D 33 62 09 69 54 D6 BD 10 B4 03 43 29 A2 B0 14 4F A7 94 DC FB 4C 51 3E B4 EE 52 00 85 7E 81 F3 09 F1 6E B3 05 79 B5 0B 69 67 24 0D B5 2D BA E3 2E 49 F7 2F 13 C3 80 7B A9 18 E9 BA 77 1D 7F 27 39 A0 A4 D9 2B BA 02 CB 65 92 59 02 6A 62 AB 96 C2 38 7F BE 24 F0 9B AC F2 17 FB DC 71 F0 CF 2A 67 83 88 2E 67 1F AE 29 34 1D C1 E3 F7 91 79 CA A5 B1 70 B4 EF 5C 33 77 21

// we verify the short block publickey: auto rsaShortVerify1 = rsaPublicKey.verify(blk, rsaShortSignature1);

  Key method Verify (PublicKey):   1

// we verify the cert:  auto rsaShortCertVerify1 = rsaCert.verify(blk, rsaShortSignature1);

  Key method Verify (Cert):   1

//We verify the precomputed hash signature: auto rsaPreComputedCertVerify1 = rsaCert.verify(blk, rsaPreComputedSignature1);

  Key method Verify pre-computed hash signature (Cert):   1

***********************
*** ECC Private Key ***
************************
 auto eccPrivateKeyData { scc::OctetString::fromHexString(
                "4cca6e8dce11d4d08218fb574c1365f076c9c94461113a971a39683d73bb5727") };
        auto eccPublicKeyData { scc::OctetString::fromHexString(
                "04"
                "b934eaca13604cadbf80dd58a8a7df9d9fe719e0b457126053533e8a792c0d2e"
                "9e0d4d6dc986064da5a88e3a86747491e0203dbd0f107bd88d29c8bbae9059e9"
                ) };
        auto eccCertData = readCert("../examples/card-Bachet-der.crt");

        sccApp.createKey(
                    0x5030,
                    "eccPrivateKey",
                    scc::SSPermission::Write,
                    scc::SSKeyType::EC_Private,
                    scc::SSKeyLen::EC_256,
                    std::move(eccPrivateKeyData)
                    );

EC Private Key ID: [5030]

// Now sign a dataset of 500*60=30K some data using it
       eccPrivateKey.initSign();

        for (int i=0; i < numBlocks-1; i++)
           eccPrivateKey.signNext(blk);

        auto eccSignature = eccPrivateKey.signFinal(blk);
//we see the signature below

  Signature:   30 46 02 21 00 AA F9 E5 DC 3A 21 DE 43 C0 6B 12 0C C3 F4 FD 09 81 95 BD 70 DE 39 33 E5 0A 11 85 79 9C C5 30 5C 02 21 00 A4 EA 1E CA F1 E0 54 31 4E DC A1 A6 44 6D 03 E0 9F 44 DA 06 40 FC 8D 89 5B 21 37 15 AD 15 70 2D
**********************
IV. ECC Public Key ***
**********************

// First create the key
        sccApp.createKey(
                    0x5031,
                    "eccPublicKey",
                    scc::SSPermission::Write,
                    scc::SSKeyType::EC_Public,
                    scc::SSKeyLen::EC_256,
                    std::move(eccPublicKeyData)
                    );
//construct an ECPublickey proxy for the key on UICC with label eccPublicKey
/scc::SCC_ECPublicKey eccPublicKey {sccApp, "eccPublicKey"};

EC Public Key ID: [5031]
Verifying ...

//Now verify the EC signature
 eccPublicKey.initVerify();

        eccPublicKey.verifyFirst(messageLen, blk);
        for (int i=0; i < numBlocks-2; i++)
           eccPublicKey.verifyNext(blk);

        auto eccVerify = eccPublicKey.verifyFinal(blk, eccSignature);

//and we see verification was successful

  Verify:  1
***********************
*** ECC Certificate ***
***********************


// First create the certificate
        sccApp.createCertificate(
                    0x5032,
                    "eccCert",
                    eccCertData
                    );

//read out the certificate -- using the ID of entry
        auto eccCertValue { sccApp.getCert(0x5032) };


Certificate: 30 82 01 9A 30 82 01 3F 02 09 00 8D 66 2A B1 E4 70 2F 57 30 0A 06 08 2A 86 48 CE 3D 04 03 02 30 81 87 31 0B 30 09 06 03 55 04 06 13 02 55 53 31 0B 30 09 06 03 55 04 08 0C 02 56 41 31 0F 30 0D 06 03 55 04 07 0C 06 44 75 6C 6C 65 73 31 0F 30 0D 06 03 55 04 0A 0C 06 47 44 4D 53 41 49 31 0B 30 09 06 03 55 04 0B 0C 02 4D 53 31 15 30 13 06 03 55 04 03 0C 0C 45 72 69 63 20 4A 6F 68 6E 73 6F 6E 31 25 30 23 06 09 2A 86 48 86 F7 0D 01 09 01 16 16 65 72 69 63 2E 6A 6F 68 6E 73 6F 6E 40 67 69 2D 64 65 2E 63 6F 6D 30 1E 17 0D 31 37 31 32 31 35 32 30 31 34 32 30 5A 17 0D 31 38 31 32 31 35 32 30 31 34 32 30 5A 30 21 31 1F 30 1D 06 03 55 04 03 0C 16 42 61 63 68 65 74 40 65 63 63 2E 69 6F 74 2E 61 74 74 2E 63 6F 6D 30 59 30 13 06 07 2A 86 48 CE 3D 02 01 06 08 2A 86 48 CE 3D 03 01 07 03 42 00 04 B9 34 EA CA 13 60 4C AD BF 80 DD 58 A8 A7 DF 9D 9F E7 19 E0 B4 57 12 60 53 53 3E 8A 79 2C 0D 2E 9E 0D 4D 6D C9 86 06 4D A5 A8 8E 3A 86 74 74 91 E0 20 3D BD 0F 10 7B D8 8D 29 C8 BB AE 90 59 E9 30 0A 06 08 2A 86 48 CE 3D 04 03 02 03 49 00 30 46 02 21 00 A5 97 90 C0 55 12 63 52 F1 A3 D4 BE 97 F0 DE C8 53 AC D1 7C 6E E2 B6 37 C2 6C 31 62 05 A1 F3 E6 02 21 00 A8 E8 05 CA 9C 12 E6 55 3B 92 D0 2A AA B8 5A D5 4D C2 CB 9C D2 30 CF AA F7 64 42 D1 05 F6 C8 24

//read out the certificate -- using the label of entry
        eccCertValue =  sccApp.getCert("eccCert");


Certificate: 30 82 01 9A 30 82 01 3F 02 09 00 8D 66 2A B1 E4 70 2F 57 30 0A 06 08 2A 86 48 CE 3D 04 03 02 30 81 87 31 0B 30 09 06 03 55 04 06 13 02 55 53 31 0B 30 09 06 03 55 04 08 0C 02 56 41 31 0F 30 0D 06 03 55 04 07 0C 06 44 75 6C 6C 65 73 31 0F 30 0D 06 03 55 04 0A 0C 06 47 44 4D 53 41 49 31 0B 30 09 06 03 55 04 0B 0C 02 4D 53 31 15 30 13 06 03 55 04 03 0C 0C 45 72 69 63 20 4A 6F 68 6E 73 6F 6E 31 25 30 23 06 09 2A 86 48 86 F7 0D 01 09 01 16 16 65 72 69 63 2E 6A 6F 68 6E 73 6F 6E 40 67 69 2D 64 65 2E 63 6F 6D 30 1E 17 0D 31 37 31 32 31 35 32 30 31 34 32 30 5A 17 0D 31 38 31 32 31 35 32 30 31 34 32 30 5A 30 21 31 1F 30 1D 06 03 55 04 03 0C 16 42 61 63 68 65 74 40 65 63 63 2E 69 6F 74 2E 61 74 74 2E 63 6F 6D 30 59 30 13 06 07 2A 86 48 CE 3D 02 01 06 08 2A 86 48 CE 3D 03 01 07 03 42 00 04 B9 34 EA CA 13 60 4C AD BF 80 DD 58 A8 A7 DF 9D 9F E7 19 E0 B4 57 12 60 53 53 3E 8A 79 2C 0D 2E 9E 0D 4D 6D C9 86 06 4D A5 A8 8E 3A 86 74 74 91 E0 20 3D BD 0F 10 7B D8 8D 29 C8 BB AE 90 59 E9 30 0A 06 08 2A 86 48 CE 3D 04 03 02 03 49 00 30 46 02 21 00 A5 97 90 C0 55 12 63 52 F1 A3 D4 BE 97 F0 DE C8 53 AC D1 7C 6E E2 B6 37 C2 6C 31 62 05 A1 F3 E6 02 21 00 A8 E8 05 CA 9C 12 E6 55 3B 92 D0 2A AA B8 5A D5 4D C2 CB 9C D2 30 CF AA F7 64 42 D1 05 F6 C8 24


//construct an ECCertificate proxy for the cert on UICC with label eccCert
        scc::SCC_ECCertificate eccCert {sccApp, "eccCert"};



EC Certificate ID: [5032]

// Now we verify the EC signature

Verifying ...

//we begin verification
eccCert.initVerify();

        eccCert.verifyFirst(messageLen, blk);
        for (int i=0; i < numBlocks-2; i++)
           eccCert.verifyNext(blk);

        auto eccCertVerify = eccCert.verifyFinal(blk, eccSignature);
//eccCertVerify is true which is to be expected

  Verify:   1

*******************************
*** ECC Convenience Methods ***
*******************************

//Finally we use the ECC application methods for small blocks
  auto eccShortSignature = sccApp.sign(
                    eccPrivateKey.getKeyId(),
                    blk,
                    scc::SSAlgorithm::ECDSA_SHA_256
                    );


Using application methods ...
  App method Signature:   30 45 02 20 7C F9 8F 6F 21 E9 A9 58 35 58 EA FC F9 37 D3 F6 1A A5 A9 A0 D9 42 8E 49 F3 FE 83 4D 1E 31 97 A3 02 21 00 B8 7B 51 0F 4C B7 39 E5 7C 7B AD 23 C0 60 22 B6 4E 8F 7B 26 44 81 79 44 FE A9 E3 A9 DC 82 A5 7E

// and now with the precomputed hash
auto eccPreComputedSignature = sccApp.sign(
                    eccPrivateKey.getKeyId(),
                    precomputedHash,
                    scc::SSAlgorithm::ECDSA_SHA_256,
                    true
                    );

  App method Signature: (pre-computed hash)  30 45 02 20 4C F3 5D 4E C9 B7 72 FE 88 78 05 AF E2 79 C5 FF 89 5E 70 2B 95 80 0A 75 29 F2 3E F4 C5 67 EE 11 02 21 00 A7 9C 7A 0F F9 62 27 07 80 6F 38 12 ED EE A8 68 A9 8B 99 67 5F 59 1D BE 45 DA AE 5E 80 4D 67 25

//we can verify publickey, cert and the pre-computed hash cert similarly to other methods

  App method Verify (PublicKey):   1
  App method Verify (Cert):   1
  Key method Verify pre-computed hash signature (Cert):   1

//finally, similar methods exist for the key objects as with other key types

Using key methods ...
  Key method Signature:   30 46 02 21 00 C4 92 4D F0 CA C1 BC BD 74 6B 70 0C 5B FD 51 A1 93 A5 52 FC E7 39 1A 3F D0 78 AA EA 90 8E 2F FF 02 21 00 EC 25 2E E1 27 42 11 36 CA D5 FF 2E 54 CC CD 01 14 06 37 37 56 B1 02 98 D8 A0 5D 5E F6 8F 63 CD
  Key method Signature (pre-computed hash): 30 46 02 21 00 F7 C6 17 BE 11 01 4A 23 8F 9C A1 D7 87 5C 11 5E EA AF 14 88 D2 47 DB B0 3A AF C2 AE 3A 8E C8 E1 02 21 00 EB CB AF A7 BE A0 8D 5E 95 E1 1E C8 11 DA 58 B0 32 2E 71 A7 C3 5F CE 2F 7C 70 81 B2 5E 10 E2 16
  Key method Verify (PublicKey):   1
  Key method Verify (Cert):   1
  Key method Verify pre-computed hash signature (Cert):   1

```

## Optional
If you require a clean version of the demo application it can be downloaded from workspaces (watchdocs). The scc-lib.zip contains the demo files.
![alt text](images/1Downloadzip.png)

Unzip and move the folder to the Raspberry pi
![alt text](images/2movefilesover.png)
