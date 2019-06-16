module AESIntSpec
( spec
)
where

import System.Process (callCommand, readProcess)
import Test.Hspec

import qualified AES.API as AES

spec :: Spec
spec = do
  describe "IO end to end" $ do
    it "should encrypt and decrypt file with 128 bit key" $ do
      encryptAndDecrypt 128

    it "should encrypt and decrypt file with 192 bit key" $ do
      encryptAndDecrypt 192
      
    it "should encrypt and decrypt file with 256 bit key" $ do
      encryptAndDecrypt 256

    it "should encrypt and decrypt 1mb file" $ do
      callCommand $ "cat /dev/urandom | head -c 1024000 > plaintext"
      AES.keygenIO 128 "aes_128.key"
      AES.keygenIO 192 "aes_192.key"
      AES.keygenIO 256 "aes_256.key"

      AES.encryptIO "aes_128.key" "plaintext" "ciphertext"
      AES.decryptIO "aes_128.key" "ciphertext" "decrypted"

      (pSha128:_) <- readProcess "sha256sum" ["plaintext"] []
      (dSha128:_) <- readProcess "sha256sum" ["decrypted"] []

      let test128 = pSha128 == dSha128

      AES.encryptIO "aes_192.key" "plaintext" "ciphertext"
      AES.decryptIO "aes_192.key" "ciphertext" "decrypted"

      (pSha192:_) <- readProcess "sha256sum" ["plaintext"] []
      (dSha192:_) <- readProcess "sha256sum" ["decrypted"] []

      let test192 = pSha192 == dSha192

      AES.encryptIO "aes_256.key" "plaintext" "ciphertext"
      AES.decryptIO "aes_256.key" "ciphertext" "decrypted"

      (pSha256:_) <- readProcess "sha256sum" ["plaintext"] []
      (dSha256:_) <- readProcess "sha256sum" ["decrypted"] []

      let test256 = pSha256 == dSha256

      callCommand "rm aes_128.key aes_192.key aes_256.key plaintext ciphertext decrypted"

      test128 && test192 && test256 `shouldBe` True

encryptAndDecrypt :: Int -> Expectation
encryptAndDecrypt keySize = do
  let keyFile = "key"
  let plaintext = "plaintext"
  let ciphertext = "ciphertext"
  let decrypted = "decrypted"
  let contents = "some longer unaligned message idk"

  callCommand $ "echo " ++ contents ++ " > " ++ plaintext

  AES.keygenIO keySize keyFile
  AES.encryptIO keyFile plaintext ciphertext
  AES.decryptIO keyFile ciphertext decrypted

  result <- readFile decrypted
  callCommand $ "rm " ++ keyFile ++ " " ++ plaintext ++ " " ++
                ciphertext ++ " " ++ " " ++ decrypted
  result `shouldBe` contents ++ "\n"